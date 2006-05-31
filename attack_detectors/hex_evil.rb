require 'gui/params_dialog.rb'

class String
  def to_hex
    ret = ''
    self.each_byte do |b|
      ret += "#{b.to_s(16)} "
    end
    ret.chop!
    return ret
    
  end
end

module FatNS
  module AttackDetection

    class EvilHex < AttackDetector
      Name = 'Evil String Detection'
      Evil = ['../../../',
              "\xCD\x80\xE8\xD7\xFF\xFF\xFF/bin/sh",
              "\x89\xF7\x29\xC7\x89\xF3\x89\xF9\x89\xF2\xAC<\xFE" ]

      def recv(pkt)
        evil_byte=false
        Evil.each do |str|
          if pkt.pre_rr.include?(str)
            evil_byte=true
            pkt.add_comment("Evil String DETECTED: #{str.to_hex}\n"+
                       "  offset from first record: #{pkt.pre_rr.index(str)}\n" + 
                       "  offset in packet:         #{pkt.pre_rr.index(str)+12}")
        end
      end
      if evil_byte
        send(pkt)
      end

    end
  end

end
end
