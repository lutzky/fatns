#!/usr/bin/ruby
require 'pcap'
require 'thread'

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

      # Returns a list of all devices that can be use for capture
      def findalldevs
        Pcap.findalldevs
      end

      # Start capuring with the specified device +dev+
      def start(dev)
        @pcapi.close unless @pcapi.nil?
        @pcapi = Pcap::Capture.open_live dev, 64*1024
      end

      # Stop capturing
      def stop
        @capture_thread.kill
      end

      # Open file
      def from_file(file)
        @pcapi = Pcap::Capture.open_offline(file)
      end

      # Save all the packets
      def to_file(file)
        #TODO allow selective saving
        pcapd=Pcap::Dumper::open(@pcapi, file)

        until @saved_packet_queue.empty?
          pcapd.dump @saved_packet_queue.pop
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
        return nil if @packet_queue.empty?
        @packet_queue.pop
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
