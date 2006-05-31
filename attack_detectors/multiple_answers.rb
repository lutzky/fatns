require 'pp'
require 'attack_detectors/all_packets'

module FatNS
  module AttackDetection

    # This detector asks the user for a number N, and records all questions
    # that received exactly N answers. This detector assumes one question
    # per DnsPacket.
    class MultipleAnswers < AllPackets
      Name = 'Multiple Answers'

      def label
        if @n
          "#@n answers"
        else
          Name
        end
      end

      def initialize
        super
        @reply_hash = {}
      end

      def recv(pkt)
        return if pkt.invalid?
        organize pkt
        return unless pkt.is_answer?

        answers = []
        question = nil

        catch :done do
          @packet_group.each_pair do |k,v|
            if v.include?(pkt)
              question = k
              answers = v
              throw :done
            end
          end
        end

        return if answers.empty?

        if answers[0].answers.size == @n
          send question
          answers.each { |a| send a }
        elsif answers[0].answers.size > @n
          revoke question
          answers.each { |a| revoke a }
        end
      end

      def set_params
        params = get_params [{:desc => 'No. of answers', :class =>Integer}]
        @n = params[0]
      end
    end
  end
end
