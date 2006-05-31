require 'capture/dnspacket'     
require 'ipaddr' # pritty printed IP address

module FatNS
  module Capture

    # = A single network packet
    # 
    # This is a packet that may carry DNS. it initializes from raw IP. will
    # be used with containers to defragment and parse dns 
    class SomePacket           

      # the HEX number assigned to ip. 
      IP_CARRIER_PROTOCOL = 0x0800 
      
      # source IPv4 address
      attr_reader :src_ip

      # destination IPv4 address
      attr_reader :dest_ip
      
      # raw data
      attr_reader :data

      # the IP id of the packet, for fragmentation
      attr_reader :packet_id

      # how offset is packet, fragment-wise
      attr_reader :fragment_offset
      
      # are there more fragments on the way (is this the last one)
      attr_reader :more_fragments

      # the time at which this packet was recievd
      attr_reader :time

      #html summary of the packet
      attr_reader :html_summary

      # gets a raw packet, with ARP stuff. will parse.
      # _raises_ ProtocolError if it can not be parsed as an IPv4 packet 
      # (most often an arp query)
      def initialize(raw_packet)

        @html_summary = ''
        @raw_packet = raw_packet.dup #save for later

        @time = Time.now


        # we assume ethernet frame 802.3 , aka ARP
        @dest_mac_addr = raw_packet.slice!(0,6).unpack('CCCCCC')
        @src_mac_addr = raw_packet.slice!(0,6).unpack('CCCCCC')
        @top_proto = raw_packet.slice!(0,2).unpack('n')[0]

        


        if @top_proto != IP_CARRIER_PROTOCOL # this is not DECnet compatible
          raise ProtocolError, "carrier protocol not IP. packet ignored. carrier protocol number is 0x"+@top_proto.to_s(16)
        end

        # store stuff for later
        @raw_ip = raw_packet.dup


        # parse IP protocol version and header size
        version_and_size = raw_packet.slice! 0
        @ip_size = (version_and_size & 0x0F) * 4
        @ip_version = (version_and_size & 0xF0) >> 4


        # check IP version 
        if @ip_version != 4
          raise ProtocolError, "IPv4 only"
        end
        
        # make shure we have enough header
        if @ip_size < 20
          raise ProtocolError, "IP Header not head enough. Please make it header."
        end

        # now slicing IP according to RFC... nothing interesting 
        @type_of_service = raw_packet.slice! 0
        


        @datagram_size = raw_packet.slice!(0,2).unpack('n')[0]



        @packet_id = raw_packet.slice!(0,2).unpack('n')[0]


        flags_and_fragment = raw_packet.slice!(0,2).unpack('n')[0]



        
        flags = flags_and_fragment & 0xf000 # the 3 flags of flaginess

        @reserved = (flags & 0x8000) != 0
        @do_not_fragment = (flags & 0x4000) != 0
        @more_fragments = (flags & 0x2000) != 0

        # FIXME: web claims 13 bits, ethereal claims 12
        @fragment_offset = (flags_and_fragment & 0x0fff)  


        @ttl = raw_packet.slice!(0)
        


        @protocol = raw_packet.slice!(0)
                

        @checksum = raw_packet.slice!(0,2).unpack('n')[0]


        @src_ip = IPAddr.new(raw_packet.slice!(0,4).unpack('CCCC').join('.'))
        @dest_ip = IPAddr.new(raw_packet.slice!(0,4).unpack('CCCC').join('.'))
        
        # get those pesky options
        if @ip_size > 20 
          @options = raw_packet.slice! 0, @ip_size-20 #xtra options
        end


        @data = raw_packet.dup

        # preform checksum
        checksum_in = @raw_ip.slice(0,@ip_size)
        checksum_in[10]=0
        checksum_in[11]=0

        c = checksum_in.checksum

        unless c == @checksum # make shure checksum is correct, drop bad checksums
          puts "CHECKSUM #{c}, should be #@checksum"
          raise ProtocolError
        end

        if not (self.tcp? or self.udp?) 
          raise ProtocolError
        end


        @html_summary += <<-END
        <h3>MAC headers</h3>
        <b>From</b> #{@src_mac_addr.collect {|o| o.to_s(16)}.join(':')}<br>
        <b>To</b> #{@dest_mac_addr.collect { |o| o.to_s(16) }.join(':')}<br>
        <br>
        END
        
        @html_summary += "<b>Recieved at:</b> #{@time.to_s} <br> <br>"

        @html_summary += "<b>IP version:</b> 0x#{@ip_version.to_s(16)} <br>"
        @html_summary += "<b>IP header size:</b> 0x#{@ip_size.to_s(16)} <br>"
        @html_summary += "<b>Type of service:</b> 0x#{@type_of_service.to_s(16)} <br>"
        @html_summary += "<b>datagram size:</b> 0x#{@datagram_size.to_s(16)} <br>"
        @html_summary += "<b>packet id:</b> 0x#{@packet_id.to_s(16)} <br>"
       @html_summary += "<h3>IP flags</h3><ul>"
        @html_summary += "<li>reserved: #{@reserved.to_s.capitalize}
                          <li>Do not fragment: #{@do_not_fragment.to_s.capitalize} 
                           <li>More fragments: #{@more_fragments.to_s.capitalize}</ul>" 
        @html_summary += "<b>fragment_offset:</b> 0x#{@fragment_offset.to_s(16)} <br>"
        @html_summary += "<b>ttl:</b> 0x#{@ttl.to_s(16)} <br>"
        @html_summary += "<b>protocol:</b> 0x#{@protocol.to_s(16)} <br>"
        @html_summary += "<b>checksum:</b> 0x#{@checksum.to_s(16)} <br>"



      end

      # is this the first packet in a cain of fragments
      def ip_first?
        @fragment_offset == 0 
      end
      
      # Is this last in a cain of fragments
      def ip_last?
        not @more_fragments
      end

      # is this packet right befor that one, fragment wise
      def ip_imediately_before?(packet)
        (@fragment_offset*8)+@datagram_size - @ip_size == (packet.fragment_offset) * 8
      end

      # is this packet before that one, fragment wise
      def ip_before(packet)
        @fragment_offset+@datagram_size >= packet.fragment_offset
      end



      # is this TCP
      def tcp?
        @protocol == 0x06
      end
      
      #is this UDP
      def udp?
        @protocol == 0x11
      end



      
      #uniq identifyer for this packet
      def uid
        "#{@src_ip.to_s} -- #{@dest_ip.to_s} -- #{@packet_id}"
      end 

    end # class
  end # module
end # module


