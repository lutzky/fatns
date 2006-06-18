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
    RCODE_TABLE = [
    ["NoError", "No Error", "[RFC1035]"], # 0
    ["FormErr", "Format Error", "[RFC1035]"], # 1
    ["ServFail", "Server Failure", "[RFC1035]"], # 2
    ["NXDomain", "Non-Existent Domain", "[RFC1035]"], # 3
    ["NotImp", "Not Implemented", "[RFC1035]"], # 4
    ["Refused", "Query Refused", "[RFC1035]"], # 5
    ["YXDomain", "Name Exists when it should not", "[RFC2136]"], # 6
    ["YXRRSet", "RR Set Exists when it should not", "[RFC2136]"], # 7
    ["NXRRSet", "RR Set that should exist does not", "[RFC2136]"], # 8
    ["NotAuth", "Server Not Authoritative for zone", "[RFC2136]"], # 9
    ["NotZone", "Name not contained in zone", "[RFC2136]"], # 10
    nil,nil,nil,nil,nil,
    ["BADVERS", "Bad OPT Version", "[RFC2671]"], # 16
    ["BADSIG", "TSIG Signature Failure", "[RFC2845]"], # 16
    ["BADKEY", "Key not recognized", "[RFC2845]"], # 17
    ["BADTIME", "Signature out of time window", "[RFC2845]"], # 18
    ["BADMODE", "Bad TKEY Mode", "[RFC2930]"], # 19
    ["BADNAME", "Duplicate key name", "[RFC2930]"], # 20
    ["BADALG", "Algorithm not supported", "[RFC2930]"] # 21
    ]
  end
end
