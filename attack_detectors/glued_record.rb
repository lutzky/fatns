require 'gui/params_dialog'

class String
  # Levels of subdomains to consist identity
  IdentityLevels = 2

  def related_to?(target)
    splitsrc = self.split('.').reverse
    splitdest = target.split('.').reverse
    if (splitsrc.size - splitdest.size).abs > IdentityLevels
      return false
    end
    if splitsrc.size > splitdest.size
      n = splitdest.size
    else
      n = splitsrc.size
    end
    0.upto(n-IdentityLevels) do |i|
      if splitsrc[i] != splitdest[i]
        return false
      end
    end
    return true
  end
end

module FatNS
  module Capture
    class DnsPacket
      def sticky?
        return false if invalid?
        return false if questions.to_a.size == 0 
        return false if additionals.to_a.size == 0
        questions.each do |q|
          additionals.each do |a|
            return true unless q.host.related_to?(a.host)
          end  
        end

        return false
      end
    end
  end

  module AttackDetection
    class GluedRecord <AttackDetector

      Name = 'Glued Record detection'

      def recv(pkt)
        send pkt if pkt.sticky?  # is that glue?
      end
    end
  end
end
