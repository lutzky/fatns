require 'attack_detectors/glued_record.rb'

module FatNS
  module Capture
    class DnsPacket
      def venomous?
        return false if invalid?
        return false if authorities.to_a.size ==0

        authorities.each do |auth|
          if auth.data.class == SOA
            return true unless
              auth.data.master_server.related_to?(auth.data.prime_server)
          end
        end

        false
      end
    end
  end

  module AttackDetection
    class PoisonedSOA < AttackDetector
      Name = 'Poisoned SOA'

      def recv(pkt)
        send pkt if pkt.venomous? # Is that a rattlesnake there?
      end
    end
  end
end
