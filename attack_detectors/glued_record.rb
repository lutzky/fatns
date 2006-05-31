require 'gui/params_dialog'




module FatNS

  module Capture
    class DnsPacket

      # Levels of subdomains to consist identity
      IdentityLevels = 2

      # does this packet look like a glued record
      def sticky?
        return false if invalid?
        return false if self.questions.to_a.size == 0 
        return false if self.additionals.to_a.size == 0
        self.questions.each do |q|
          self.additionals.each do |a|
            hq = q.host.split('.').reverse
            ha = a.host.split('.').reverse
            0.upto(IdentityLevels-1) do |i|
              if hq[i] !=  ha[i]
                return true
              end
            end
          end  
        end

        return false
      end

      def dsticky?
        return false if invalid?
        return false if questions.to_a.size == 0 
        return false if additionals.to_a.size == 0
        questions.each do |q|
          additionals.each do |a|
            hq = q.host.split('.').reverse
            ha = a.host.split('.').reverse
            if (hq.size-ha.size).abs > IdentityLevels
              return true
            end
            if hq.size>ha.size
              n=ha.size
            else
              n=hq.size
            end
            0.upto(n-IdentityLevels) do |i|
              if hq[i] !=  ha[i]
                return true
              end
            end
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
        send pkt if pkt.dsticky?  # is that glue?
      end


    end
  end
end
