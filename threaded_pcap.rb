#!/usr/bin/ruby
require 'pcap'
require 'thread'
require 'pp'

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

class Queue
  def copy
    temp = Queue.new
    result = Queue.new
    until self.empty?
      temp << self.pop
    end
    until temp.empty?
      obj = temp.pop
      self << obj
      result << obj
    end
    result
  end
end

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
        @capture_thread = nil
        @client_packet_queue = Queue.new
        @saved_packet_queue = Queue.new
      end

      # Start capuring with the specified device +dev+
      def start(dev)
        @pcapi.close unless @pcapi.nil?
        @saved_packet_queue.clear
        @pcapi = Pcap::Capture.open_live dev, 64*1024
        capture_loop
      end

      # Stop capturing
      def stop
        @capture_thread.kill unless @capture_thread.nil?
        @capture_thread = nil
      end

      # Open file
      def from_file(file)
        stop
        @pcapi = Pcap::Capture.open_offline(file)
        capture_loop
      end

      # Save all the packets
      def to_file(file)
        #TODO allow selective saving
        pcapd=Pcap::Dumper::open(@pcapi, file)

        packets_for_file = @saved_packet_queue.copy
        until packets_for_file.empty?
          pcapd.dump packets_for_file.pop
        end
        pcapd.close
      end

      # Returns a new packet if such is available, or +nil+ otherwise.
      #
      # == Usage example
      #
      #   dcap=DnsCapture.new
      #   dcap.start(dcap.findalldevs[0])
      #   while true
      #     do stuff
      #     
      #     pkt = poll
      #  
      #     unless pkt.nil?
      #       do more stuff with pkt
      #     end
      #   end
      #   dcap.stop
      def poll
        return nil if @client_packet_queue.empty?
        @client_packet_queue.pop
      end

      class << self
        # Returns a list of all devices that can be use for capture
        def findalldevs
          begin
          Pcap.findalldevs
          rescue
            return [] # you haven't ehough permissions to do this
          end
        end
      end

      def replay
        stop
        @client_packet_queue = @saved_packet_queue.copy
      end

      private 
      def capture_loop
        return unless @capture_thread.nil?

        @capture_thread = Thread.new do
          @pcapi.each_packet do |pkt|
            @client_packet_queue << pkt
            @saved_packet_queue << pkt
          end
        end
      end
    end
  end
end
