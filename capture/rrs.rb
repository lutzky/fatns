require 'ipaddr'
require 'time'

require 'capture/dnstype'
require 'capture/qclass'
require 'capture/soa'
require 'capture/typeparse'
require 'capture/dns_string'

module FatNS
  module Capture



    # failed being a valid packet
    class ValidityError < Exception
    end

    # Mail Exchange record
    class MX

      # will parse itself from the packet
      def initialize(raw_dns,orig)
        @pref = raw_dns.network_short!
        @host = raw_dns.uncompress!(orig)
      end

      def to_s
        "#@pref #@host" 
      end
    end




    # generic RR class. nothing much here
    class RR

      # give a type and a piece of raw dns, 
      # and this function parses acordingly
      def type_parse(type,raw_dns)
        case type
        when 1 # A
          return IPAddr.new(raw_dns.unpack('CCCC').join('.'))
        when 2..5 # NS MD MF CNAME
          return raw_dns.uncompress!(@original)
        when 6 # !!!! SOA !!!!
          return SOA.new(raw_dns,@original)
        when 7..9 # MB MG MR nothing important
          return raw_dns.uncompress!(@original)
        when 10 # NULL
          return nil
        when 11 # WKS == unknown
          return raw_dns
        when 12 # PTR
          return raw_dns.uncompress!(@original)
        when 13..14 # HINFO,MINFO = unknown
          return raw_dns
        when 15 # MX
          return MX.new(raw_dns,@original)
        when 16 # TXT
          return raw_dns.uncompress!(@original)
        when 17..27
          return raw_dns
        when 28 # AAAA IPv6
          return IPAddr.new(raw_dns.unpack('nnnnnnnn').join(':'))
        when 29..255 ### much unused stuff
          return raw_dns
        end
      end
    end



    # sore dns questions
    # contains
    # * host - uncompressed dns hostname
    # * qclass - a dns query class
    # * type - dns query type 
    class Question < RR
      include FatNS::Truisms 

      attr_reader :host,:type,:qclass, :invalid,:raw

      # constructs a dns question from the raw data, and the original unparsed dns structure
      def initialize(raw_dns,orig)
        begin
          @raw=raw_dns.dup
          @original=orig.dup
          @host= raw_dns.uncompress!(@original)
          @type  = raw_dns.network_short!
          @qclass = raw_dns.network_short!
        rescue
          @invalid=true
        end
      end

      def to_html
        if QCLASS_TABLE[@qclass] and DNS_TABLE[@type]
          "<i>[#{QCLASS_TABLE[@qclass][0]}]</i> <b>#{DNS_TABLE[@type][0]}</b>: #@host"
        else
          puts "Invalid class #{@qclass.to_s(16)}, type #{@type.to_s(16)}"
        end
      end

      # Concise textual summary of the question
      def summary
        if QCLASS_TABLE[@qclass] and DNS_TABLE[@type]
          "[#{QCLASS_TABLE[@qclass][0]}] #{DNS_TABLE[@type][0]} #@host"
        else
          puts "invalid class #{@qclass.to_s(16)}  type #{@type.to_s(16)}"
        end
      end

      alias_method :to_s, :summary
    end




    # sore dns Records
    # contains
    # * host - uncompressed dns hostname
    # * class - a dns query class
    # * type - dns query type
    # * ttl - ttl
    # * data - a data field of type type
    class Record < RR
      include FatNS::Truisms 


      attr_reader :host,:type,:qclass,:ttl,:data, :invalid, :raw, :pre_data

      # construct an answer/Authority/additional from raw dns and the original unparsed packet
      def initialize(raw_dns,orig)
        begin
          # save original
          @original=orig.dup
          @raw=raw_dns.dup

          # slice by rfc
          @host=raw_dns.uncompress!(@original)
          @type  = raw_dns.network_short!
          @qclass = raw_dns.network_short!
          @ttl   = raw_dns.network_long!
          @data_length=raw_dns.network_short!
          @pre_data=raw_dns.slice!(0,@data_length)

          # use type parsing function
          @data = type_parse(@type,@pre_data)
        rescue
          @invalid=true
        end

      end

      def to_html
        begin
          data_html = @data.to_html
        rescue
          data_html = @data.to_s
        end

        begin
          return "<i>[#{QCLASS_TABLE[@qclass][0]}]</i> <b>#{DNS_TABLE[@type][0]}</b> <code>#@host</code>: <code>#{data_html}</code>"
        rescue
          return "<i>[#@qclass]<i> <b>#@type</b> <code>#@host</code>: #{data_html}"
        end
      end

      def summary
        if QCLASS_TABLE[@qclass] and DNS_TABLE[@type]
          "[#{QCLASS_TABLE[@qclass][0]}] #{DNS_TABLE[@type][0]} #@host"
        else
          "bad class or type"
        end
      end
    end # class
  end # module 
end # module
