require 'gui/params_dialog.rb'

module FatNS
  module AttackDetection

    # Matches a regular expression against the full DnsPacket description
    class RegexpSearch < AttackDetector
      Name = 'Regexp Search'

      def label
        if @search_ex
          Name + ': ' + @search_ex.source
        else
          Name
        end
      end

      def set_params
        params = get_params([{:desc => 'Regular expression', :class => String}])

        raise 'No search string received' if params[0].empty?

        @search_ex = Regexp.new params[0]
      end

      def recv(pkt)
        send pkt if pkt.to_searchstring =~ @search_ex
      end
    end
  end
end

