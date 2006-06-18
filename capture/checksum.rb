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
 
