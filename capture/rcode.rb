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
