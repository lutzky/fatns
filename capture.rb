#!/usr/bin/ruby
require 'threaded_pcap'
require 'capture/packet'
require 'capture/ipcontainer'
require 'capture/tcpcontainer'

# This file is part of FatNS, a DNS sniffing and attack detection tool.
# Copyright (C) 2006 Ohad Lutzky and Boaz Goldstein
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

module FatNS 

  # = Packet capturing and handling
  #
  # This module comtains all the classes that describe the insides of various
  # types of packets, network protocols and of course the interface to Pcap's
  # capture routeens
  module Capture

    # = Capturing interface. 
    #
    # A capturing interface that works well with single threaded gui apps.
    # can save and load captures, and start a live capture from a device. 
    class DnsCapture

      # A hash of flags used to filter out non-dnspackets.
      # This lets you set options on initial filtering of packets.
      # See ValidationDefaults
      attr_reader :validate_dns

      # Default values for #validate_dns
      # [+check_by_port+]   Reject packets not from port 53
      # [+udp_only+]        Reject non-UDP packets
      # [+tcp_only+]        Reject non-TCP packets
      # [+check_structure+] Check for DNS structure validity.
      #                     <b>Warning</b> this will ignore some forms of attack
      ValidationDefaults = {
        :check_by_port => true,
        :only_udp => false,
        :only_tcp => false,
        :check_structure => false,
        :ignore_altman => false
      }


      def initialize # :nodoc:
        @validate_dns = ValidationDefaults
        @tcap = ThreadedPcap.new

        @ip_fixer = Hash.new
        @tcp_fixer = Hash.new
      end

      # Returns a list of all devices that can be use for capture
      def findalldevs
        ThreadedPcap.findalldevs
      end

      # Start capuring with the specified device +dev+
      def start(dev)
        @tcap.start dev
        @poll=true
      end

      # Stop capturing
      def stop
        @tcap.stop
        @poll=false
      end

      # Open file
      def from_file(file)
        @poll=true
        @tcap.from_file(file)
      end

      # Save all the packets
      def to_file(file)
        #TODO allow selective saving
        @tcap.to_file(file)
      end

      def replay
        @tcap.replay
      end

      # return array of DnsPackets
      #
      # == Usage example
      #   dcap=DnsCapture.new
      #   dcap.start(dcap.findalldevs[0])
      #   while true
      #     do stuff
      #     
      #     arr = poll 100
      #  
      #     do more stuff with arr
      #   end
      #
      def poll(i)
        return [] if not @poll

        # loop on packets
        new_packets = []
        #puts "Attempting to get at most #{i} packets"
        catch :no_more_packets do
          1.upto(i) do |unused_variable_name|
            pkt = @tcap.poll
            if pkt
              new_packets << pkt
            else
              throw :no_more_packets
            end
          end
        end

        return_dns = []

        new_packets.each do |raw_pkt|
          return_dns += process_packet(raw_pkt)
        end

        return return_dns
      end




      # a simple interface to get all packets in queue/file
      def get_all_packets

        # loop on packets
        new_packets = []
        #puts "Attempting to get at most #{i} packets"
        catch :no_more_packets do
          while true do  
            pkt = @tcap.poll
            if pkt
              new_packets << pkt
            else
              throw :no_more_packets
            end
          end
        end
        #puts "Got #{new_packets.length} packets"

        return_dns = []

        new_packets.each do |raw_pkt|
          return_dns += process_packet(raw_pkt)
        end

        return return_dns
      end

      def process_packet(raw_pkt)
        #puts 'pkt'+rand.to_s
        return_dns = Array.new
        begin
          # parse the raw IP
          packet = SomePacket.new(raw_pkt.raw_data)
        rescue ProtocolError # ignore malformed IP or ARP
          return []
        end

        # filter out protocols that cannot carry dns
        next unless (packet.tcp? or packet.udp?)

        # defrag
        if @ip_fixer[packet.uid].nil?
          @ip_fixer[packet.uid] = IpContainer.new packet 
        else
          @ip_fixer[packet.uid].add packet 
        end

        # if we have a complete IP packet 
        if @ip_fixer[packet.uid].complete?
          @ip_fixer[packet.uid].protocol_parse
          pstream=@ip_fixer[packet.uid]
          if pstream.tcp?
            begin # TCP dies ugly

              # complete all the pakets in the tcp stream
              if @tcp_fixer[pstream.tcp_uid].nil?
                @tcp_fixer[pstream.tcp_uid] = TcpContainer.new pstream 
              else
                @tcp_fixer[pstream.tcp_uid].add(pstream) 
              end

              # has this stream FINed and 
                pstream = @tcp_fixer[pstream.tcp_uid]
            rescue TcpError # kill connection
              @tcp_fixer[pstream.tcp_uid] = nil
              pstream=nil

            rescue TcpReset # RESET. just close and start a new one
              @tcp_fixer[pstream.tcp_uid] = nil
              pstream=nil
            end
          end

          # the pstream was not nilled, it has some DNS in it
          if not pstream.nil?
            pstream.dns_each(validate_dns) do |dns| # duck typed IP/TCP
            return_dns << dns
          end

          # nil out done TCP streams
          if packet.tcp? && pstream.complete?
            @tcp_fixer[pstream.uid] = nil
          end
        end
        # nil out fragmented IP packets
        @ip_fixer[packet.uid] = nil
      end
      return return_dns
    end
  end
end
end
