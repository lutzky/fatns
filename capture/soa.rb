module FatNS
  module Capture

    ### SOAs are so ugly they get a class of their own
    class SOA

      attr_reader :prime_server,:dude_incharge,
      :serial, :refresh, :retry, 
      :expire, :minttl, :slaves


      def initialize(raw_data,orig)
        begin
          @prime_server=raw_data.uncompress!(orig)
          @dude_incharge=raw_data.uncompress!(orig)

          @serial = raw_data.slice!(0,4).unpack('N')[0]
          @refresh = raw_data.slice!(0,4).unpack('N')[0]
          @retry = raw_data.slice!(0,4).unpack('N')[0]
          @expire = raw_data.slice!(0,4).unpack('N')[0]
          @minttl = raw_data.slice!(0,4).unpack('N')[0]
        end


      end
      #@\([a-z]+\)^/0x#{$1.to_s(16)

      def to_html
        begin
          ret = <<-HERE    
          <h3>Start Of Authority Record</h3>
          <table>
          <tr><td><b>Primary server</b></td><td>#@prime_server</td></tr>
          <tr><td><b>Master</b></td><td>#@dude_incharge</td></tr>
          <tr><td><b>Serial</b></td>        <td>0x#{@serial.to_s(16)}</td></tr>
          <tr><td><b>Refresh</b>            <td>0x#{@refresh.to_s(16)}</td></tr>
          <tr><td><b>Retry</b>              <td>0x#{@retry.to_s(16)}</td></tr>
          <tr><td><b>Expire</b>             <td>0x#{@expire.to_s(16)}</td></tr>
          <tr><td><b>Minimum TTL</b>        <td>0x#{@minttl.to_s(16)}</td></tr>
          </table>
          HERE

          ret
        rescue
          puts "something went wrong: #{$@} , #{$!}"

        end

      end

    end # class
  end # module
end # module
