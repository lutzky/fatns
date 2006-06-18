# This file is part of FatNS, a DNS sniffing and attack detection tool.
# Copyright (C) 2006 Ohad Lutzky and Boaz Goldstein
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

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
