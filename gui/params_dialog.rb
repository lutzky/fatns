require 'gtk2'

module FatNS
  module GUI

    # Graphically receive parameters for an attack detector. The
    # syntax for +params+ is the same as
    # AttackDetection::AttackDetector.get_params.
    def GUI.get_params(params = [], title = 'Parameters')
      dlg = Gtk::Dialog.new(title, nil,
        Gtk::Dialog::MODAL | Gtk::Dialog::DESTROY_WITH_PARENT,
        [Gtk::Stock::OK, Gtk::Dialog::RESPONSE_OK],
        [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL]
      )

      table = Gtk::Table.new params.length, 2, false
      table.set_column_spacings 2
      dlg.vbox.pack_start table

      widgets = []

      params.each_with_index do |p,i|
        # Note: Use to_s on the class here, otherwise
        # class comparison will be done inappropriately
        # with ===.
        widgets[i] = case p[:class].to_s
                     when "String": Gtk::Entry.new
                     when "Integer": Gtk::SpinButton.new(
                       Gtk::Adjustment.new(0,-2**32,2**32,1,0,0),
                       1,
                       0)
                     else nil
                     end

        table.attach_defaults((p[:desc]+':').to_label, 0,1,i,i+1)
        table.attach_defaults(widgets[i], 1,2, i, i+1)

        raise "Invalid parameter class #{p[:class]}" if widgets[i].nil?
      end

      dlg.vbox.show_all
      response = dlg.run

      results = []

      0.upto(params.length-1) do |i|
        results[i] = 
        case params[i][:class].to_s
        when "String": widgets[i].text
        when "Integer": widgets[i].text.to_i
        else raise # We really shouldn't get here
        end
      end
      dlg.destroy

      throw :cancel if response != Gtk::Dialog::RESPONSE_OK

      results
    end
  end
end
