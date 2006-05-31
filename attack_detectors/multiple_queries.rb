require 'pp'
require 'attack_detectors/all_packets'

module FatNS
  module AttackDetection

    # This detector asks the user for a number N, and records all questions
    # that received exactly N answers. This detector assumes one question
    # per DnsPacket.
    class MultipleQueries < AttackDetector
      Name = 'Multiple queries'

      def label
        if @n > -1
          "#@n queries"
        elsif @n
          ">1 queries"
        else

          Name
        end
      end

      def initialize
        super
        @reply_hash = {}
      end

      def recv(pkt)
        @queries = {} if not @queries
        puts pkt.class
        return if not pkt.valid? or pkt.is_answer?
        @queries[pkt.questions[0].host] = [] if not @queries[pkt.questions[0].host]       
        @queries[pkt.questions[0].host] << pkt 

        if @n >= 0
          puts 'there' + @queries[pkt.questions[0].host].size.to_s
          if @queries[pkt.questions[0].host].size == @n 
            @queries[pkt.questions[0].host].each do |i|
              send i
            end
          elsif @queries[pkt.questions[0].host].size == @n+1
            @queries[pkt.questions[0].host].each do |i|
              revoke i
            end
          end
        else
          puts 'here' + @queries[pkt.questions[0].host].size.to_s
          if @queries[pkt.questions[0].host].size == 2
            @queries[pkt.questions[0].host].each do |i|
              send i
            end
          elsif @queries[pkt.questions[0].host].size > 2
            send pkt
          end
        end

      end

      def set_params
        params = get_params [{:desc => 'No. of queries (negitive for "more than 1")', :class =>Integer}]
        @n = params[0]
      end


      # queries for the same host
      def group?(p1,p2)
        (not p1.invalid?) and
        (not p2.invalid?) and
        p1.questions_num > 0 and
        p2.questions_num > 0 and
        p1.questions[0].host == p2.questions[0].host
      end
    end
  end
end
