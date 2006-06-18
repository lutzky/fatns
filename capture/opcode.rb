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

module FatNS
  module Truisms
    OPCODE_TABLE = [
    ["Query", "[RFC1035]"], # 0 
    ["OpCode Retired", "[RFC3425]"], # 1
    ["Status", "[RFC1035]"], # 2
    ["reserved", "[IANA]"], # 3
    ["Notify", "[RFC1996]"], # 4
    ["Update", "[RFC2136]"] # 5
    ]
  end
end
