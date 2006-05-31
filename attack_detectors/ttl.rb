require 'gui/params_dialog.rb'

module FatNS
  module AttackDetection

    # Matches a regular expression against the full DnsPacket description
    class TTLLimit < AttackDetector
      Name = 'TTL Limit'

      def label
        if @max_ttl
          Name + ': ' + @max_ttl.to_s
        else
          Name
        end
      end

      def set_params
        params = get_params([{:desc => 'Low TTL is', :class => Integer}])

        @max_ttl = params[0]
      end

      def recv(pkt)
        flag = false
        (pkt.answers.to_a + pkt.authorities.to_a +
        pkt.additionals.to_a).each_with_index do |r,i|
          if r.ttl <= @max_ttl
            flag = true
            pkt.add_comment "TTL: RR \##{i} has a TTL lower than #@max_ttl"
          end
        end
        send pkt if flag
      end
    end
  end
end
