require 'gui/params_dialog.rb'
require 'attack_detectors/all_packets.rb'

module FatNS
  module AttackDetection

    #check recursion

    class Iterative < AllPackets 
      Name = 'Non-recurively answered'

      def recv(pkt)
        return if pkt.invalid?
        organize pkt
        return unless pkt.is_answer?
        return if pkt.recursion_wanted

        answers = []
        question = nil

        catch :done do
          @packet_group.each_pair do |k,v|
            if v.include?(pkt)
              question = k
              answers  = v
              throw :done
            end
          end
        end

        if answers.size == 1
          send question
        end
          send pkt
      end
    end
  end
end
