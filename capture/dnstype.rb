#!/usr/bin/ruby

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
    DNS_TABLE = [
    nil, # 0
    ["A", "a host address", "[RFC1035]"], # 1
    ["NS", "an authoritative name server", "[RFC1035]"], # 2
    ["MD", "a mail destination (Obsolete - use MX)", "[RFC1035]"], # 3
    ["MF", "a mail forwarder (Obsolete - use MX)", "[RFC1035]"], # 4
    ["CNAME", "the canonical name for an alias", "[RFC1035]"], # 5
    ["SOA", "marks the start of a zone of authority", "[RFC1035]"], # 6
    ["MB", "a mailbox domain name (EXPERIMENTAL)", "[RFC1035]"], # 7
    ["MG", "a mail group member (EXPERIMENTAL)", "[RFC1035]"], # 8
    ["MR" ,"a mail rename domain name (EXPERIMENTAL)[RFC1035]"], # 9
    ["NULL", "a null RR (EXPERIMENTAL)", "[RFC1035]"], # 10
    ["WKS", "a well known service description", "[RFC1035]"], # 11
    ["PTR", "a domain name pointer", "[RFC1035]"], # 12
    ["HINFO", "host information", "[RFC1035]"], # 13
    ["MINFO", "mailbox or mail list information", "[RFC1035]"], # 14
    ["MX", "mail exchange", "[RFC1035]"], # 15
    ["TXT", "text strings", "[RFC1035]"], # 16
    ["RP", "for Responsible Person", "[RFC1183]"], # 17
    ["AFSDB", "for AFS Data Base location", "[RFC1183]"], # 18
    ["X25", "for X.25 PSDN address", "[RFC1183]"], # 19
    ["ISDN", "for ISDN address", "[RFC1183]"], # 20
    ["RT", "for Route Through", "[RFC1183]"], # 21
    ["NSAP", "for NSAP address, NSAP style A record", "[RFC1706]"], # 22
    ["NSAP-PTR" ,""], # 23
    ["SIG", "for security signature", "[RFC2535], [RFC3755], [RFC4034]"], # 24
    ["KEY", "for security key", "[RFC2535], [RFC3755], [RFC4034]"], # 25
    ["PX", "X.400 mail mapping information", "[RFC2163]"], # 26
    ["GPOS", "Geographical Position", "[RFC1712]"], # 27
    ["AAAA", "IP6 Address", "[Thomson]"], # 28
    ["LOC", "Location Information", "[RFC1876]"], # 29
    ["NXT", "Next Domain - OBSOLETE", "[RFC2535, RFC3755]"], # 30
    ["EID", "Endpoint Identifier", "[Patton]"], # 31
    ["NIMLOC", "Nimrod Locator", "[Patton]"], # 32
    ["SRV", "Server Selection", "[RFC2782]"], # 33
    ["ATMA", "ATM Address", "[Dobrowski]"], # 34
    ["NAPTR", "Naming Authority Pointer", "[RFC2168, RFC2915]"], # 35
    ["KX", "Key Exchanger", "[RFC2230]"], # 36
    ["CERT", "CERT", "[RFC2538]"], # 37
    ["A6", "A6", "[RFC2874]"], # 38
    ["DNAME", "DNAME", "[RFC2672]"], # 39
    ["SINK", "SINK", "[Eastlake]"], # 40
    ["OPT", "OPT", "[RFC2671]"], # 41
    ["APL", "APL", "[RFC3123]"], # 42
    ["DS", "Delegation Signer", "[RFC3658]"], # 43
    ["SSHFP", "SSH Key Fingerprint", "[RFC-ietf-secsh-dns-05.txt]"], # 44
    ["IPSECKEY", "IPSECKEY", "[RFC4025]"], # 45
    ["RRSIG", "RRSIG", "[RFC3755]"], # 46
    ["NSEC", "NSEC", "[RFC3755]"], # 47
    ["DNSKEY", "DNSKEY", "[RFC3755]"], # 48

    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], 

    ["SPF", "NON EXISTANT", "[RFC-schlitt-spf-classic-02.txt]"], # 99
    ["UINFO", "NON EXISTANT", "[IANA-Reserved]"], # 100
    ["UID", "NON EXISTANT", "[IANA-Reserved]"], # 101
    ["GID", "NON EXISTANT", "[IANA-Reserved]"], # 102
    ["UNSPEC", "NON EXISTANT", "[IANA-Reserved]"], # 103

    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],
    ['','',''], ['','',''], ['','',''], ['','',''], ['','',''],

    ["TKEY", "Transaction Key", "[RFC2930]"], # 249
    ["TSIG", "Transaction Signature", "[RFC2845]"], # 250
    ["IXFR", "incremental transfer", "[RFC1995]"], # 251
    ["AXFR", "transfer of an entire zone", "[RFC1035]"], # 252
    ["MAILB", "mailbox-related RRs (MB, MG or MR)", "[RFC1035]"], # 253
    ["MAILA", "mail agent RRs (Obsolete - see MX)", "[RFC1035]"], # 254
    ["*", "A request for all records", "[RFC1035]"], # 255
    ]

    # This function gives you the matching DNS query type id
    # for a given type identifier string, +s+.
    def Truisms.get_dnstype_id(s)
      DNS_TABLE.each_with_index do |t,i|
        return i if (not t.nil?) and t[0] == s
      end
      raise "Invalid DNS Type #{_type}"
    end


  end
end
