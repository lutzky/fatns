require 'gui/params_dialog.rb'

module FatNS
  module AttackDetection

    class Birthday < AttackDetector

      Name = 'Birthday attacks'

      # if no new berthday attack style packets are added in
      # this much time, the attack is consedered to be over
      TimeOut = 2

      def label
        if @exp
          "2^#{@exp} #{Name}"
        else
          Name
        end
      end

      def set_params
        params = get_params [{:desc => 
        'minimal size of birthday attacks (power of 2):  2 ^ ', 
        :class => Integer}] 
        @exp = params[0]
      end

      # assumes packets come in, in cronological order. if not, FIXME
      def recv(pkt)
        # make sure it's all initialized
        @answers = {} if not @answers  
        @questions = {} if not @questions
        @detected = {} if not @detected

        # get arr of packet
        # this has the side-effect of confirming the packet is ok
        catch :bad_packet do
          arr = arr_of pkt

          if not arr
            # array doesnt exists. create it
            if pkt.is_answer?
              @answers[pkt.questions[0].host] = []
            else
              @questions[pkt.questions[0].host] = []
            end
            arr_of(pkt) << pkt
            @detected[pkt.questions[0].host] = false

          else
            # is this a new attack
            if ((arr.size > 0) and (pkt.time - arr.last.time) > TimeOut)

              # get rid of the old one (it's saved in the packet tree)
              @questions[pkt.questions[0].host] = []
              @answers[pkt.questions[0].host] = []
              @detected[pkt.questions[0].host] = false
            else 
            end
              arr_of(pkt) << pkt
          end


          # is the attack big enough to be considered birthday attack? 
          if @questions[pkt.questions[0].host].to_a.size > 2**@exp and @answers[pkt.questions[0].host].to_a.size > 2**@exp  
            if not @detected[pkt.questions[0].host]
              (@questions[pkt.questions[0].host] + @answers[pkt.questions[0].host]).each do |sendme|
                sendme.add_comment "this seems to be part of a birthday addack"
                send sendme
              end
              @detected[pkt.questions[0].host] = true
            else
              pkt.add_comment "this seems to be part of a birthday addack"
              send pkt
            end
          else

          end
        end
      end

      def arr_of(pkt)
        if (not pkt.questions) or (not pkt.questions[0])
          throw :bad_packet
        end
        if pkt.is_answer?
          return @answers[pkt.questions[0].host]
        else
          return @questions[pkt.questions[0].host]
        end

      end

      def group?(p1,p2)
        if p1.is_question?
          @questions[p2.questions[0].host].include?(p1) 
        else
          @answers[p2.questions[0].host].include?(p1)
        end
      end


    end
  end
end
