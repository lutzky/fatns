module FatNS
  module AttackDetection

    # All packet detector - detects all packets. This isn't an _attack_
    # detector per se, obviously...
    class AllPackets < AttackDetector
      Name = 'All Packets'

      def recv(pkt)
        organize pkt
        send pkt
      end

      def initialize
        super
        @packet_group = {}
        @packet_list = []
      end

      def organize(pkt)
        if not pkt.is_answer?
          @packet_list.unshift(pkt)
          @packet_group[pkt]=[]
        else 
          p = @packet_list.find { |p2| pkt.query_id == p2.query_id }
          if p
            @packet_group[p] << pkt
          else
            @packet_list.unshift(pkt)
            @packet_group[pkt]=[]
          end
        end
      end

      # assumes packet 1 is in the tree
      def group?(p1,p2)
        if @packet_group[p1].nil? 
          return false
        end
        (@packet_group[p1].member?(p2))
      end

    end
  end
end
