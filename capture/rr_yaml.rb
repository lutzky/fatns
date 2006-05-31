require 'yaml'
require 'ipaddr'
require 'capture/rrs'

# = YAML exporting
#
# This YAML exporting and importing of RRs is meant for saving known results,
# in an effort to detect spoofing attacks.

# This is an extension to IPAddr to allow clean YAML dumping. Simply
# use YAML dumping as you normally would
class IPAddr
  def to_yaml_type
    "!ruby/ipaddr"
  end
  def to_yaml( opts = {} )
    YAML::quick_emit(self.object_id, opts) { |out|
      out << "#{to_yaml_type} "
      self.to_s.to_yaml(:Emitter => out)
    }
  end
end

YAML.add_ruby_type(/^ipaddr/) { |type, val|
  IPAddr.new(val)
}

module FatNS
  module Capture
    class Record
      def to_yaml_properties
        %w{ @qclass @type @host @data }
      end
      def to_yaml(opts = {})
        YAML::quick_emit(self.object_id, opts) { |out|
          out.map(to_yaml_type) { |map|
            map.add('qclass', QCLASS_TABLE[@qclass][0])
            map.add('type', DNS_TABLE[@type][0])
            map.add('host', @host)
            map.add('data', @data)
          }
        }
      end
      def to_yaml_type
        '!cs.technion.ac.il,2006/record'
      end
    end
    class Question
      def to_yaml_properties
        %w{ @qclass @type @host }
      end
      def to_yaml(opts = {})
        YAML::quick_emit(self.object_id, opts) { |out|
          out.map(to_yaml_type) { |map|
            map.add('qclass', QCLASS_TABLE[@qclass][0])
            map.add('type', DNS_TABLE[@type][0])
            map.add('host', @host)
          }
        }
      end
      def to_yaml_type
        '!cs.technion.ac.il,2006/question'
      end
    end
  end
end

YAML.add_domain_type('cs.technion.ac.il,2006','record') do |type, val|
  val['type'] = FatNS::Truisms.get_dnstype_id(val['type'])
  val['qclass'] = FatNS::Truisms.get_qclass_id(val['qclass'])

  YAML.object_maker(FatNS::Capture::Record,val)
end

YAML.add_domain_type('cs.technion.ac.il,2006','question') do |type, val|
  val['type'] = FatNS::Truisms.get_dnstype_id(val['type'])
  val['qclass'] = FatNS::Truisms.get_qclass_id(val['qclass'])

  YAML.object_maker(FatNS::Capture::Record,val)
end
