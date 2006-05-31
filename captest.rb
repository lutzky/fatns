#!/usr/bin/ruby 

require 'capture'

cap=FatNS::Capture::DnsCapture.new
cap.start('eth1')
#cap.from_file('bork_dumps/lots_of_dns')
while(1)
  a=cap.poll(1)
  a.each { |i| puts i}
end
