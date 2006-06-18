require 'capture/rrs'
require 'capture/opcode'
require 'capture/rcode'

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
    # Basic DNS packet class
    class DnsPacket
      include FatNS::Truisms 

      # Array of questions
      attr_reader :questions 

      # Array of answers
      attr_reader :answers 

      # Array of uthorities
      attr_reader :authorities 

      # Array of additionals
      attr_reader :additionals 

      # the IP packet from whence this came
      attr_reader :source 

      # The return opcode from the server
      attr_reader :rcode 

      # is this answer authenticated / should the answer to this question be authenticated
      attr_reader :is_authd 

      # Can this server recurse
      attr_reader :recursion_ok 

      # Do we want this query to be recursive
      attr_reader :recursion_wanted 

      # How many authorities did we get
      attr_reader :authorities_num 

      # How many addtionals did we get
      attr_reader :additionals_num 

      # How many answers did we get
      attr_reader :answers_num 

      # How many questions did we get
      attr_reader :questions_num 

      # the query id of this query
      attr_reader :query_id 

      # the question opcode (see table)
      attr_reader :opcode 

      # is this message truncated
      attr_reader :is_truncated 

      # is this server an authority on the subject
      attr_reader :is_authority 

      # the time this packet was completed
      attr_reader :time

      # the binary data before we read the RR's
      attr_reader :pre_rr

      # Add a comment to this packet. This is meant to be used by attack
      # detectors, which will provide insight relevant to their attack
      # analysis.
      def add_comment(comment)
        @comments << comment
      end

      # is this a question or answer?
      def is_answer?
        @is_answer
      end

      def is_question?
        not @is_answer
      end

      MIN_DNS = 12 # you cant have less data in dns

      # can be used multiple times, for multiple dns queries in one TCP stream
      # 
      # parses and checks validity of a stream based on passed validity check parameters:
      #
      # * check_by_port - only port 53 packets, answers from 53 and questions to 53
      # * only_tcp - ignore udp packets
      # * only_udp - ignore tcp pckets
      # * check_structure - only valid dns packets (useful when ignoring port 53 ssh)
      def initialize(source,data,params = {})


        
        @comments = []
        p=data.dup
        @source=source
        
        @raw_data=data
        @orig=data.dup

        @invalid=false
        @size=0

        # save the state of the TCP stream if TCP. 
        # this is a mere optimization for UDP
        @source_html=@source.html_summary

        # time this DNS pacet was completed
        @time = @source.time.dup

        
        
        # toss out wrong ports
        if params[:check_by_port]
          if (not (@source.src_port == 53)) and (not (@source.dest_port == 53))
            raise ProtocolError
          end
        end

        raise ProtocolError if params[:only_udp] and not @source.udp?
        raise ProtocolError if params[:only_tcp] and not @source.tcp?

        if @raw_data.length < MIN_DNS # verify size
          raise ProtocolError
        end


        # much parsing...



        @query_id  = @raw_data.network_short!
        @size+=2


        flags  = @raw_data.network_short!
        @rcode =           (flags & 0x000f)               #reply
        @is_authd =           (flags & 0x0020)  >> 5  == 1   #reply
        @reserved_dns_flag =  (flags & 0x0040)  >> 6  == 1 
        @recursion_ok =      (flags & 0x0080)  >> 7  == 1   #reply 
        @recursion_wanted =  (flags & 0x0100)  >> 8  == 1
        @is_truncated =       (flags & 0x0200)  >> 9  == 1
        @is_authority =       (flags & 0x0400)  >> 10 == 1   #reply
        @opcode =             (flags & 0x7800)  >> 11
        @is_answer =          (flags & 0x8000)  >> 15 == 1
        @size+=2


        @questions_num    = @raw_data.network_short!
        @answers_num      = @raw_data.network_short!
        @authorities_num  = @raw_data.network_short!
        @additionals_num  = @raw_data.network_short!
        @size+=8


        @pre_rr = @raw_data.dup
        # cut out questions, answers, authorities and aditionals

        begin

          @questions=Array.new
          @questions_num.downto(1) do |i|
            q = Question.new(@raw_data, @orig)
            @questions << q
          end

          @answers=Array.new
          @answers_num.downto(1) do |i|
            a = Record.new(@raw_data,@orig)
            @answers << a
          end


          @authorities=Array.new
          @authorities_num.downto(1) do |i|
            a = Record.new(@raw_data,@orig)
            @authorities << a
          end

          @additionals=Array.new
          @additionals_num.downto(1) do |i|
            a = Record.new(@raw_data,@orig)
            @additionals << a
          end

        rescue ValidityError
          @invalid=true
        end
        (@questions.to_a + 
        @answers.to_a + 
        @authorities.to_a + 
        @additionals.to_a 
        ).each do |rr|
          @invalid=true if rr.invalid
        end

        # confirm port directions
        if params[:check_by_ports]
          if ((@dest_port != 53) && is_question?) || 
            ((@src_port != 53) && (not is_question?))
            raise ProtocolError
          end
        end

        # if we need valid structure
        if params[:check_structure] and @invalid
          puts 'invalid'
          raise ProtocolError
        end
      end

      # would this be taken by the check_structure validation?
      def invalid?
        @invalid
      end

      # is this valid
      def valid?
        not invalid?
      end

      # the source IP adress (four int array)
      def from
        @source.src_ip
      end

      #the destination ip address 
      def to
        @source.dest_ip
      end

      # source_port
      def to_port
        @source.dest_port
      end

      # target_port
      def from_port
        @source.src_port
      end

      # did this com over udp?
      def udp?
        @source.udp?
      end

      # did this come over tcp?
      def tcp?
        @source.tcp?
      end

      # Short textual summary of the packet contents
      def summary
        if is_question?
          if @questions.size > 0
            @questions[0].summary
          else
            "[!] QUESTIONLESS QUESTION"
          end
        else
          if @answers.to_a.size > 0
            @answers[0].summary
          elsif @authorities.to_a.size > 0
            @authorities[0].summary
          elsif @additionals.to_a.size > 0
            @additionals[0].summary
          elsif @questions.to_a.size > 0
            "[!] #{@questions[0].summary}"
          else
            "BLANK RESPONSE - NO RESOURCE RECORDS"
          end
        end
      end

      def to_long_html
        to_html + "<h1>Additional Information</h1>" + @source_html
      end

      # Long concatenation of all useful data about this packet, for searching
      # against
      def to_searchstring
        str = self.from.to_s + ' ' + self.to.to_s + ' ' +
              @source.src_port.to_s + ' ' + @source.dest_port.to_s + ' '+
              query_id.to_s(16) + ' '
        (@questions.to_a + @answers.to_a +
         @authorities.to_a + @additionals.to_a).each do |q|
           str += q.summary + ' '
         end

         str
      end

      # Complete textual information about the packet
      def to_html
        if @invalid
          ret = "<h1>Invalid DNS Packet</h1>"
          if @comments.length > 0
            ret += "<h2>Detected attacks</h2><ul><li>" +
            @comments.join("</li><li>") + "</li></ul>"
          end
          ret += "<h2>Complete packet hexdump</h2><pre>\n"
          i=0
          @orig.each_byte do |b|
            i+=1
            ret += ' ' if i==8 
            if i==16 
              i=0
              ret += "\n"
            end
            ret += "0x#{b.to_s(16)} "
          end
          ret += "</pre>"
        return ret 
        end

        ret = "<h1>DNS #{is_question? ? 'Question' : 'Answer[s]'}</h1>"

        if @comments.length > 0
          ret += "<h3>detected attacks<h3><ul><li>" +
          @comments.join("</li><li>") + "</li>"
        end

        ret += <<-END
        <ul>
        <li><b>From:</b> #{@source.src_ip.to_s}:<i>#{@source.src_port}</i>
        <li><b>To:</b> #{@source.dest_ip.to_s}:<i>#{@source.dest_port}</i>
        <li><b>Protocol:</b> #{@source.udp? ? 'UDP' : 'TCP'}
        </ul>

        <h2>Flags</h2>
        <ul>
        <li><b>Recursion request:</b>  #@recursion_wanted
        <li><b>Truncation flag:</b>    #@is_truncated
        <li><b>Packet opcode:</b>      #{OPCODE_TABLE[@opcode][0]}
        <li><b>Is this an answer:</b>  #@is_answer
        END

        if @is_answer
          ret += <<-END
          <li><b>Reply opcode:</b>       #{RCODE_TABLE[@rcode][0]}
          <li><b>Recursion OK:</b>       #@recursion_ok
          <li><b>Record flag:</b>        #@is_authority
          <li><b>Authenticated?</b>      #@is_authd
          END
        end

        ret += "</ul>"

        ret += <<-END
        <h2>Payload counters</h2>
        <ul>
        <li>#@questions_num questions
        <li>#@answers_num answers
        <li>#@authorities_num authorities
        <li>#@additionals_num additionals
        </ul>
        END

        [ :questions, :answers, :authorities, :additionals ].each do |sym|
          arr = eval('@' + sym.to_s)
          unless arr.empty?
            ret += "<h2>#{sym.to_s.capitalize}</h2><ul>"
            arr.each do |item|
              ret += "<li>#{item.to_html}</li>"
            end
            ret += "</ul>"
          end
        end

        ret
      end

    end # class 
  end # module
end # module
