

# MIX IN

class String 

# this code was "translated" from perl. it may lack readability (^_^)
  def checksum
    plen = self.length
    num = (plen / 2).to_i
    chk = 0
    count = plen

    arr = self.unpack("n#{num}")
    arr.each do |short|
        chk += short
        count = count - 2
    end

    if(count == 1) 
        chk += self[plen]
    end
    # add the two halves together (CKSUM_CARRY -> libnet)
    chk = (chk >> 16) + (chk & 0xffff)
    ~((chk >> 16) + chk) & 0xffff

  end
end
 
