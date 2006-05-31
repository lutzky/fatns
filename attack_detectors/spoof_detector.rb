require 'yaml'

module FatNS
  module AttackDetection
    class SpoofDetector < AttackDetector
      Name = 'Spoof Detector'

      def initialize
        super
        @known_dns = File.open('known_dns.yml') { |yf| YAML::load(yf) }
      end

      def recv(pkt)
        return unless pkt.is_answer?

        @known_dns.each do |d| 
          if d.matches_question?(pkt)
            unless d.matches_answer?(pkt)
              pkt.add_comment <<-EOF
SpoofDetector: This answer is different than the one we have on file!
              EOF
              send pkt
            end
            return
          end
        end
      end
    end
  end

  module Capture
    class Question
      def ==(tgt)
        self.host   == tgt.host   and
        self.qclass == tgt.qclass and
        self.type   == tgt.type
      end
    end

    class Record
      def ==(tgt)
        self.host        == tgt.host        and
        self.qclass      == tgt.qclass      and
        self.type        == tgt.type        and
        self.data        == tgt.data
      end
    end

    class DnsPacket
      def matches_question?(tgt)
        return false if self.invalid?
        return false unless self.questions.size == tgt.questions.size

        self.questions.each do |q|
          return false unless tgt.questions.include?(q)
        end
      end

      def matches_answer?(tgt)
        return false if self.invalid?
        return false unless self.answers.size == tgt.answers.size
        return false unless self.authorities.size == tgt.authorities.size
        return false unless self.additionals.size == tgt.additionals.size

        self.answers.each do |q|
          return false unless tgt.answers.include?(q)
        end
        self.authorities.each do |q|
          return false unless tgt.authorities.include?(q)
        end
        self.additionals.each do |q|
          return false unless tgt.additionals.include?(q)
        end
      end
    end
  end
end
