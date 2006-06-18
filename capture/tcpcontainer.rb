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

    class TcpError < Exception # please kill connection if one of these happenes
    end

    class TcpReset < Exception # RST flag.
    end

    # = TCP stream understanding container
    # 
    # this holds a TCP stream, will accept packets for that tcp stream
    class TcpContainer


      # the time the latest packet in this stream was recieved
      attr_reader :time
      
      # the id of the stream (with a name for polymorphism)
      attr_reader :packet_id

      # source fort
      attr_reader :src_port
      
      # destination port
      attr_reader :dest_port
      
      # source ip address
      attr_reader :src_ip

      # a fuzzy bunny rabit
      attr_reader :dest_ip

      def tcp?
        true
      end

      def udp?
        false
      end

      

      

      # expects an IpContainer. ducktype for compatibility
      def initialize(packet)

        # cant start with an ack
        if packet.ack?
          raise TcpError
        end


        # set state of stateful stream
        @state='clean'

        # is the stream complete
        @complete = false

        @data={}

        # set inittial time
        @time = packet.time

        # all accepted packets
        @packets = Hash.new

        # arrays in directions depending on the packet 
        @packets[packet.tcp_to]=Array.new
        @packets[packet.tcp_from]=Array.new

        # packets who's data has not been given an ack
        @unacked=Hash.new
        @unacked[packet.tcp_to]=Array.new
        @unacked[packet.tcp_from]=Array.new

        # save some data
        @src_port   = packet.src_port
        @dest_port  = packet.dest_port
        @src_ip     = packet.src_ip
        @dest_ip    = packet.dest_ip



        # confirm flags
        if packet.syn? and not packet.ack?

          # set tcp uid
          @uid = packet.tcp_uid
          # save
          @packets[packet.tcp_to] <<  packet
          #update state
          @state='syn'
          # remember who is server and who is client
          @server=packet.tcp_to
          @client=packet.tcp_from

        else
          raise TcpError # cant have a connection wihtout the first syn 
        end
        @html_summary = "<br> #{packet.html_summary}"
      end

      # add packet to stream. assumes packet belongs
      def add(packet)
        # check for a reset
        if packet.rst?
          raise TcpReset
        end
        

        @html_summary += "<br> #{packet.html_summary}"
        @time = packet.time
        
        # we act by state
        case @state
        when 'syn'
          if packet.syn? and packet.ack? and @packets[packet.tcp_from][0]
            @state='synack'
            @packets[packet.tcp_to] << packet
          elsif packet.syn?
            @packets[packet.tcp_from][0] = packet
          else
            raise TcpError
          end
        when 'synack'
          if (packet.ack? and 
            (not packet.syn?) and 
            @packets[packet.tcp_from][0]  and 
            @packets[packet.tcp_to][0])

            @packets[packet.tcp_to] << packet
            @state='connected' 
          elsif (packet.ack? and 
            (packet.syn?) and 
            @packets[packet.tcp_from][0] and 
            @packets[packet.tcp_to][0])
            @packets[packet.tcp_to][0]=packet
          else
            raise TcpError
          end

        when 'connected'  
          if  packet.syn? # no syning when connected
            raise TcpError
          elsif packet.fin? #fin!
            @state="fin #{packet.tcp_to}"
            process_packet(packet)
          else
            process_packet(packet)
          end
        when 'ignore' # i am irrelevent. do nothing
          if packet.fin? #fin!
            @state="fin #{packet.tcp_to}"
          end
        # waiting for from to fin
        when "fin #{packet.tcp_to}"
          process_packet(packet)

        # when from is waiting for to to fin
        when "fin #{packet.tcp_from}"
          process_packet(packet) #check for ACKs
          if (packet.fin?)
            @complete=true # i dont care about the return ack. 
          end

        end
      end

      def html_summary
        "<h2>TCP stream</h2>
        <b>From</b> <code>#@client</code><br>
        <b>To</b> <code>#@server</code><br>
        <b>State</b> <code>#@state</code> 
        #@html_summary"
      end

      private

      # given a packet, this will place it in the stream, and use it's acks
      def process_packet(packet)
        if packet.syn? # this should not process SYN packets
          raise TcpError
        end

        @unacked[packet.tcp_to].each do |p2| # check for dup
          if p2.tcp_identical(packet)
            return false
          end
        end

        @packets[packet.tcp_to].each do |p2| # check for dup
          if p2.tcp_identical(packet)
            return false
          end
        end

        if packet.ack? # should be true, or there will be dead
          # process acks. if packet data was acked, move to ackedvil
          @unacked[packet.tcp_from].each_with_index do |p2,i|
            if (p2.seq_num + p2.tcp_size) <= packet.ack_num
              @unacked[packet.tcp_from].delete_at(i)
              @packets[packet.tcp_from] << p2
            end
          end
        end    
        # store unacked packet
        @unacked[packet.tcp_to] << packet 
      end

      public

      #uniq identifyer 
      def uid
        @uid
      end
  
      # has this stream FIN't
      def complete?
        @complete #optimization
      end


      # duck-typed dns-each.
      # will process all dns packets in the stream, first client and the server
      def dns_each(params = {})
        # sort stream
        @packets.each_pair do |k,packet_array|
          packet_array.sort! do |a,b| # probably FIXME, nicer way
            (a.seq_num) <=> (b.seq_num)
          end
        end

        # for each side
        [@server,@client].each do |key|
          # follect all data fom all packets
          prev=nil
          catch :gap do
            @packets[key].each do |pkt|
              if prev.nil? 
                prev = pkt
              else
                throw :gap unless prev.tcp_next(pkt)
                prev = pkt
              end
              @data[key] = '' if @data[key].nil?
              @data[key] += pkt.tcp_data
              pkt.mark
            end
          end

          begin
            break if @data[key].nil?
            while(@data[key].length>0)
              # slice
              size = @data[key].slice(0,2).unpack('n')[0]
              # check validity
              break if(size.nil? or @data[key].length < size)

              # cut by given size 
              size = @data[key].slice!(0,2).unpack('n')[0]
              unit=@data[key].slice!(0,size)

              # make and yield
              dns = DnsPacket.new(self,unit,params)
              yield(dns)
            end
          rescue ProtocolError
            @state = 'ignore'
            puts "ignoreing #@uid"
            return 
          end
        end
      end 

    end
  end
end


