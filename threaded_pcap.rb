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
      end


      private 
      def capture_loop
      end

      end
    end
  end
