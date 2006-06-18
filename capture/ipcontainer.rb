require 'capture/somepacket'
require 'capture/dnspacket'
require 'capture/checksum'

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
  module Capture

    # IP reconstruction container
    # 
    # reconstructs fragmented ip packets. handle parsing of TCP and UDP headers. 
    # make dns
    class IpContainer
      attr_reader :html_summary

      # the id of the packets being reconstructe
      attr_reader :packet_id

      # source port
      attr_reader :src_port

      # target port
      attr_reader :dest_port

      # the time at which the *first* packet wes recived
      # TODO deprecated
      # attr_reader :time

      # the raw data:
      attr_reader :data


      # expects a new somepacket. will probably die in horrible agony otherwise
      # (Ducketype to avoid this)
      def initialize(packet)

        @mark = false

        # array of packets that contain the same piece of data
        @packets = Array.new

        # this packet is not complete
        @complete = false

        # set this packet's ID
        @packet_id = packet.packet_id

        # put this in the array. we do an insertion sort
        @packets[0] = packet
        if(packet.ip_first? && packet.ip_last?)
          # this packet is not fragmented
          @complete=true
        end
      end

      # will drop packet if it dont belong, will not warn
      def add(packet)
        # make shure packet belongs
        return if(packet.packet_id != @packet_id)

        i=0
        # find place in array
        while ( i< @packets.size && @packets[i].ip_before(packet) ) 
          i += 1
        end
        @packets.insert(i,packet) # and put it there
      end

      #uniq identifyer 
      def uid
        "#{@packet[0].src_ip.to_s} -- #{@packet[0].dest_ip.to_s} -- #{@packet_id}"
      end

      # check if the packet is compl33t
      def complete?
        return true if @complete #optimization
        # firstnes, lastnes 
        if not (@packets[0].ip_first? and @packets.last.ip_last?)
          return false
        end
        flag=true

        # is all the stuff in the middle there?
        0.upto(@packets.size-2) do |i|
          if not @packets[i].ip_imediately_before?(@packets[i+1])
            flag=false
          end
        end


        if flag
          @complete=true
          return true
        else
          return false
        end

      end


      # size of data in packet(s)
      def data_size
        data = ''
        @packets.each do |pkt|
          data += pkt.data
        end
        data.length
      end


      # parse the protocol headers
      def protocol_parse
        @data = ''
        @packets.each do |pkt|
          @data += pkt.data
        end
        raw_packet=@data.dup
        # this is good for both TCP and UDP
        @src_port = raw_packet.slice!(0,2).unpack('n')[0]
        @dest_port = raw_packet.slice!(0,2).unpack('n')[0]

        if self.udp?
          @udp_length = raw_packet.slice!(0,2).unpack('n')[0]
          @udp_checksum = raw_packet.slice!(0,2).unpack('n')[0]
          @length = @udp_length

          @html_summary = <<-EOF
          <h3>UDP Packet</h3>
          <ul>
          <li><b>From:</b> #{self.src_ip}:<i>#@src_port</i></li>
          <li><b>To:</b> #{self.dest_ip}:<i>#@dest_port</i></li>
          <li><b>Length:</b> 0x#{@length.to_s(16)}</li>
          <li><b>Checksum:</b> 0x#{@udp_checksum.to_s(16)}</li>
          </ul>
          EOF
        end

        if self.tcp? # My god is TCP *ugly*
          @tcp_seq_num = raw_packet.slice!(0,4).unpack('N')[0]
          @tcp_ack_num = raw_packet.slice!(0,4).unpack('N')[0]
          offset_reserved_flags = raw_packet.slice!(0,2).unpack('n')[0]
          @tcp_offset = ((offset_reserved_flags & 0xf000) >> 12)*4
          flags = (offset_reserved_flags & 0x00bf) 
          @tcp_flag_urg = (flags & 0x20) != 0
          @tcp_flag_ack = (flags & 0x10) != 0
          @tcp_flag_psh = (flags & 0x8) != 0
          @tcp_flag_rst = (flags & 0x4) != 0
          @tcp_flag_syn = (flags & 0x2) != 0
          @tcp_flag_fin = (flags & 0x1) != 0
          @tcp_window = raw_packet.slice!(0,2).unpack('n')[0]
          @tcp_checksum = raw_packet.slice!(0,2).unpack('n')[0]
          @tcp_urg_ptr = raw_packet.slice!(0,2).unpack('n')[0]
          @tcp_options = raw_packet.slice!(0,@tcp_offset - 20) # options

          @html_summary = <<-EOF
          <h3>TCP Packet[s]</h3>
          <ul>
          <li><b>From:</b> #{self.src_ip}:<i>#@src_port</i>
          <li><b>To:</b> #{self.dest_ip}:<i>#@dest_port</i>
          <li><b>Seq num:</b> 0x#{@tcp_seq_num.to_s(16)}
          <li><b>Ack num:</b> 0x#{@tcp_ack_num.to_s(16)}
          <li><b>TCP Offset:</b> 0x#{@tcp_offset.to_s(16)}
          <li><b>Window:</b> 0x#{@tcp_window.to_s(16)}
          <li><b>Checksum:</b> 0x#{@tcp_checksum.to_s(16)}
          <li><b>Urg Ptr:</b> 0x#{@tcp_urg_ptr.to_s(16)}
          </ul>
          Flags:
          <ul>
          <li><b>Urg:</b> #@tcp_flag_urg
          <li><b>Ack:</b> #@tcp_flag_ack
          <li><b>Psh:</b> #@tcp_flag_psh
          <li><b>Rst:</b> #@tcp_flag_rst
          <li><b>Syn:</b> #@tcp_flag_syn
          <li><b>Fin:</b> #@tcp_flag_fin
          </ul>
          EOF
        end

        @html_summary += '<h3>Packet fragments</h3>'

        @packets.each do |pkt|
          @html_summary += pkt.html_summary
        end


        @raw_data = raw_packet
      end

      # the time the packet was completed
      def time
        @packets.last.time
      end

      def tcp?
        @packets[0].tcp?
      end

      def udp?
        @packets[0].udp?
      end

      def src_ip
        @packets[0].src_ip
      end

      def dest_ip
        @packets[0].dest_ip
      end

      def syn?
        @tcp_flag_syn
      end

      def ack?
        @tcp_flag_ack
      end

      def rst?
        @tcp_flag_rst
      end

      def ack_num
        @tcp_ack_num
      end

      def seq_num
        @tcp_seq_num 
      end

      def fin?
        @tcp_flag_fin
      end

      def tcp_size
        data_size - @tcp_offset
      end

      # data in packet (in case of tcp)
      def tcp_data
        return '' if @mark
        d=@data.dup
        d.slice!(0,@tcp_offset)
        return d
      end


      def mark
        @mark=true
      end

      def tcp_next(n)
        if [n.seq_num,n.seq_num - 1].include?(
          @tcp_seq_num +
          @data.to_s.length - 
          @tcp_offset)  
          return true
        else
          return false
        end
      end


      # is this a duped packet?
      def tcp_identical(packet)
        @data == packet.data 
      end

      # the TCP uid (source port+ip, target port+ip)
      def tcp_uid
        if(@src_port>@dest_port)
          return "#{self.src_ip.to_s}|#{self.dest_ip.to_s}|#@src_port|#@dest_port"
        else
          return "#{self.dest_ip.to_s}|#{self.src_ip.to_s}|#@dest_port|#@src_port"
        end
      end

      def to_html
        "IP Container source"
      end

      # the target of this pacet (string)
      def tcp_to
        "#{self.dest_ip} #@dest_port"    
      end

      # the source of this packet (string)
      def tcp_from
        "#{self.src_ip} #@src_port"  
      end


      # step through each dns packet in this ip packet (should be one) 
      def dns_each(params = {})
        begin
          data=@raw_data.dup
          dns = DnsPacket.new(self,data,params)
          yield(dns)
        rescue ProtocolError
          return 
        end
      end 

    end # class
  end # module
end # module
