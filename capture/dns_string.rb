    class String
      # uncompress DNS $sys$loathsome compression
      def uncompress!(orig)
        len=self.slice!(0)            #         \\|//
        if not len                    #         |`^'| 
                                      #         \\-// 
          raise FatNS::Capture::ValidityError#   ###  
        end
        ret=''
        while(len>0 && len<128)            
          raise FatNS::Capture::ValidityError if len+1 > self.length
          ret += self.slice!(0,len)        
          len=self.slice!(0)              
          (ret += '.') if(len>0)              
        end
        if(len>128)
          offset  = (len << 8) +self.slice!(0) # 2 byte context
          offset &= 0x3fff # top 2 bits are flags. clear them!
          new_raw_dns=orig.dup
          new_raw_dns.slice!(0,offset)
          ret += new_raw_dns.uncompress!(orig) 
        end
        return ret                                       

      end

      # slice a network endian short
      def network_short!
        self.slice!(0,2).unpack('n')[0]
      end


      # slice a network endian long
      def network_long!
        self.slice!(0,4).unpack('N')[0]
      end


    end


