require 'capture'

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
  module GUI

    # Simple control with a start/stop button and pulsating
    # progress bar, used to control packet capturing. Capturing
    # does not take place while this control is stopped, but
    # does in-between quantas.
    class CaptureControl < Gtk::Frame
      # Amount of packets to poll for each time
      POLL_AMOUNT = 150
      # How often to poll for packets
      TIMEOUT = 150

      # The DNS Capture object
      attr_reader :dnscapture

      # Upon initialization, you must supply a process to gather
      # the packets captured. For example,
      #
      #   arr = Array.new
      #   cc = CaptureControl.new { |p| arr << p }
      def initialize(&packet_proc) # :yields: packet
        super 'Capture control'

        hbox = Gtk::HBox.new false
        hbox.border_width = 3

        add hbox

        height_request = 32

        @dnscapture = Capture::DnsCapture.new

        @btn_Start = Gtk::Button.new
        hb = Gtk::HBox.new
        hb.pack_start Gtk::Image.new(Gtk::Stock::MEDIA_PLAY,
                                     Gtk::IconSize::BUTTON)
        hb.pack_start 'Start capturing'.to_label
        @btn_Start.add hb

        @btn_Stop = Gtk::Button.new
        hb = Gtk::HBox.new
        hb.pack_start Gtk::Image.new(Gtk::Stock::STOP,
                                     Gtk::IconSize::BUTTON)
        hb.pack_start 'Stop capturing'.to_label
        @btn_Stop.add hb

        @btn_Replay = Gtk::Button.new
        hb = Gtk::HBox.new
        hb.pack_start Gtk::Image.new(Gtk::Stock::REDO,
                                     Gtk::IconSize::BUTTON)
        hb.pack_start 'Replay'.to_label
        @btn_Replay.add hb

        @btn_Stop.sensitive = false

        @btn_Start.signal_connect('clicked') { start_capture }
        @btn_Stop.signal_connect('clicked') { stop_capture }
        @btn_Replay.signal_connect('clicked') { replay }

        @cmb_Interface = Gtk::ComboBox.new


        temp_devs = @dnscapture.findalldevs
        if temp_devs.empty?
          @btn_Start.sensitive = false
        end


          temp_devs.reject { |dev| dev == 'any' }.each do |iface|
            @cmb_Interface.append_text iface
          end

          @cmb_Interface.active = 0

          @progressbar = Gtk::ProgressBar.new

          hbox.pack_start @btn_Start, false, false
          hbox.pack_start @btn_Stop, false, false
          hbox.pack_start @btn_Replay, false, false
          hbox.pack_start @cmb_Interface, false, false
          hbox.pack_end @progressbar, false, false

          @packet_proc = packet_proc
        end

        # Start capturing now. This is visible in the GUI.
        def start_capture
          begin
            iface = @cmb_Interface.active_iter[0]
            raise if iface.empty?
          rescue
            dlg = Gtk::MessageDialog.new(
                                         self.toplevel, Gtk::MessageDialog::DESTROY_WITH_PARENT,
                                         Gtk::MessageDialog::ERROR, Gtk::MessageDialog::BUTTONS_CLOSE,
          'No capture interface selected.'
                                        )
                                        dlg.signal_connect('response') do |widget, data|
                                          widget.destroy
                                        end
                                        dlg.show
          else
            catch :cancel do
              toplevel.clear
              toplevel.lock true
              @dnscapture.start iface
              @cmb_Interface.sensitive = false
              @btn_Start.sensitive = false
              @btn_Replay.sensitive = false
              @btn_Stop.sensitive = true
              @capture_timeout = Gtk.timeout_add(TIMEOUT) { capture_quanta }
            end
          end
        end

        # Save currently recorded packets to file +filename+
        def save(filename)
          @dnscapture.to_file(filename)
        end

        # Load +filename+ as a pcap capture and run it.
        def load(filename)
          @dnscapture.from_file(filename)
          @dnscapture.get_all_packets.each { |packet| @packet_proc.call(packet) }
        end

        def replay
          toplevel.clear true
          @dnscapture.replay
          @dnscapture.get_all_packets.each { |packet| @packet_proc.call(packet) }
        end

        # Stop capturing now. This is visible in the GUI.
        def stop_capture
          @dnscapture.stop
          Gtk.timeout_remove @capture_timeout
          @cmb_Interface.sensitive = true
          @btn_Start.sensitive = true
          @btn_Replay.sensitive = true
          @btn_Stop.sensitive = false
          @progressbar.fraction = 0
          toplevel.lock false
        end

        private
        def capture_quanta
          @progressbar.pulse

          @dnscapture.poll(POLL_AMOUNT).each do |packet|
            @packet_proc.call(packet)
          end

          true
        end
      end
    end
  end
