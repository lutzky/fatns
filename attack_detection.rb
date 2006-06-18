require 'capture/dnspacket'
require 'gtk2'
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

module FatNS
  # = Attack detector architecture
  #
  # This is a mechanism which allows you to write your own attack detectors for
  # FatNS. To write your own detector, subclass AttackDetector (please read the
  # details in the documentation for AttackDetector). Place all detectors in
  # the +attack_detectors+ directory, and give them a <tt>.rb</tt> extension.
  # For a simple detector, which 'detects' all incoming packets, see
  # all_packets.rb.
  module AttackDetection

    # This is a generic attack detector, which detects no packets. It is meant
    # to be subclassed by actual attack detectors.
    #
    # An attack detector works as follows - upon initialization, +set_params+
    # is called. If you receive external parameters, you'll want to override
    # this.
    # 
    # When running, the attack detector is sent all incoming DnsPacket objects
    # via the +recv+ method. At this point, it may evaluate the incoming
    # packets, save some for later, do whatever it likes with them. At any
    # point, it can choose to send packets onwards, using the +send+ method.
    # This displays them in the main FatNS screen, in a tab specially created
    # for the detector.
    class AttackDetector
      # The name of your detector as shown in the menu
      Name = 'Generic attack'

      # The label for your detector's tab (defaults to +Name+)
      def label
        self.class::Name
      end

      def initialize(&send_proc) # :nodoc:
        @send_proc = send_proc
        set_params
      end

      # This method will supply the attack detector a mechanism with which
      # to request the interface to remove packets from display.
      def set_revoke(&revoke_proc) # :yields: packet
        @revoke_proc = revoke_proc
      end

      # This method will be called every time a packet is received, with the
      # appropriate packet.
      def recv(pkt)
      end

      # This method is used to decide whether two packets should be grouped
      # together in the packet display. The default is to group by query ids.
      # If this function returns true, +pkt1+ and +pkt2+ are grouped together.
      def group?(pkt1, pkt2)
        false
      end

      # This method will be called when a new capture starts, or when a
      # clear is explicitly requested. Override this method if you save
      # intermediate information.
      def clear
      end

      protected
      # To get additional parameters for your detector, redefine the
      # +set_params+ method. You are encouraged to use +get_params+ to actually
      # receive your parameters from the user. You may also raise an exception
      # during +set_params+, and it will be properly displayed in the
      # application.
      def set_params
      end

      # Ask the interface to remove the specified packet from display
      def revoke(pkt)
        @revoke_proc.call(pkt)
      end

      # Send a packet back to the interface.
      def send(pkt)
        @send_proc.call(pkt)
      end

      # Use this method for requesting parameters from the user. +params+ is a
      # array of hashes of the following form:
      #
      #   [ { :class => String, :desc => 'Description' }, ... ]
      #
      # Currently allowed classes are String, Integer
      def get_params(params)
        GUI.get_params(params, 'Parameters for ' + self.class::Name)
      end
    end

    # Load all available attack detectors
    def AttackDetection.initialize
      Dir.glob('attack_detectors/*.rb').each do
        |detector|
        require detector
      end
    end

    # Get a list of all available attack detectors (as strings)
    def AttackDetection.get_detectors
      AttackDetection.constants.collect {
        |c| AttackDetection.module_eval(c)
      } - [ AttackDetector ]
    end
  end
end
