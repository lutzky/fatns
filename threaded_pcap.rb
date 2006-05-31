#!/usr/bin/ruby
require 'pcap'

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
    class ThreadedPcap

      def initialize # :nodoc:
        @pcapi = nil
      end

      # Returns a list of all devices that can be use for capture
      def findalldevs
        Pcap.findalldevs
      end

      # Start capuring with the specified device +dev+
      def start(dev)
        @pcapi.close if not @pcapi.nil?
        @all_packets = Array.new
        @pcapi = Pcap::Capture.open_live( dev, 64*1024)
        @poll=true
      end

      # Stop capturing
      def stop
        @poll=false
      end

      # Open file
      def from_file(file)
        @poll=true
        @all_packets = Array.new
        @dns_packets = Array.new
        @pcapi = Pcap::Capture.open_offline(file)
      end

      # Save all the packets
      def to_file(file)
        #TODO allow selective saving
        pcapd=Pcap::Dumper::open(@pcapi, file)
        arr = @all_packets
        arr.each do |packet|
          pcapd.dump(packet)
        end
        pcapd.close
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
          1.upto(10*i) do |unused_variable_name|
            pkt = @pcapi.get_packet
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
          # save packet for file save
          @all_packets << raw_pkt
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
            pkt = @pcapi.get_packet
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
          # save packet for file save
          @all_packets << raw_pkt
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
