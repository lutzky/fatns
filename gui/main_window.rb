require 'pp'
require 'gtk2'
require 'gui/packet_tree'
require 'gui/capture_control'

require 'attack_detection'

class String
  # Get a new Gtk::Label object from this string.
  def to_label
    Gtk::Label.new self
  end
end

module FatNS
  module GUI

    # Tab labels for the attack detector notebook
    class TabLabel < Gtk::HBox
      def initialize(string, &destroy_proc)
        super false, 4
        @has_packets = false
        @string = string
        @label = @string.to_label
        pack_start @label, true
        evbox = Gtk::EventBox.new
        evbox.set_visible_window false
        evbox.add Gtk::Image.new(Gtk::Stock::CLOSE,Gtk::IconSize::MENU)
        evbox.signal_connect('button_press_event') { destroy_proc.call }
        pack_end evbox, false, false
        show_all
      end

      def set_bold(flag)
        if flag
          @label.markup = "<b>#@string</b>"
        else
          @label.markup = @string
        end
      end

    end

    # Main window for FatNS
    class MainWindow < Gtk::Window
      OptionTogglers = {
        :check_by_port   => Gtk::CheckMenuItem.new('Check by port'),
        :only_udp        => Gtk::CheckMenuItem.new('Only UDP'),
        :only_tcp        => Gtk::CheckMenuItem.new('Only TCP'),
        :check_structure => Gtk::CheckMenuItem.new('Check structure') 
      }

      # Handle 'new packets here' notification for the given page. If +fresh+
      # is +true+, the label for +page+ is set to bold - otherwise boldness
      # is unset.
      # +page+ can either be the index of the page in the notebook or the actual
      # page object.
      def page_notify(page, fresh)
        page = @notebook.get_nth_page(page) if page.is_a? Fixnum

        @notebook.get_tab_label(page).set_bold fresh
      end

      # Quit FatNS
      def quit
        destroy
      end

      # Call this when capture starts, to prevent all disruptions to the
      # capture process.
      def lock(locked)
        @menubar.sensitive = !locked
      end

      # Clear all packets from all detectors. This asks the user whether
      # he wants to do this or not, unless +force+ is set to +true+.
      def clear(force = false)
        return unless @has_packets

        unless force
          dialog = Gtk::MessageDialog.new nil,
            Gtk::Dialog::MODAL | Gtk::Dialog::DESTROY_WITH_PARENT,
            Gtk::MessageDialog::WARNING, Gtk::MessageDialog::BUTTONS_YES_NO,
            'This will clear all captured packets. Are you sure?'

          result = dialog.run
          dialog.destroy

          throw :cancel unless result == Gtk::Dialog::RESPONSE_YES
        end

        0.upto(@notebook.n_pages - 1) do |i|
          @notebook.get_nth_page(i).clear
          page_notify i, false
        end
        @detectors.each { |d| d.clear }

        @has_packets = false
      end

      def initialize
        super 'FatNS'

        @has_packets = false

        screen = Gdk::Screen.default
        set_default_size screen.width * 0.85, screen.height * 0.85
        vbox = Gtk::VBox.new false, 2
        @capcontrol = CaptureControl.new { |pkt| recv_packet pkt }

        @notebook = Gtk::Notebook.new
        @notebook.tab_pos = Gtk::POS_TOP
        @notebook.signal_connect('switch-page') do |notebook, page, page_num|
          page_notify page_num, false
        end

        @detectors = []

        AttackDetection.initialize

        add_detector_page AttackDetection::AllPackets

        @menubar = create_menu

        vbox.pack_start @menubar, false, false
        vbox.pack_start @capcontrol, false, false
        vbox.pack_start @notebook, true, true

        self.add vbox
      end

      # Sends received packet to all relevant filters, for passing
      # to relative tabs.
      def recv_packet(pkt)
        @has_packets = true

        @detectors.each do |detector|
          detector.recv pkt
        end
      end

      def save_cap
        dialog = Gtk::FileChooserDialog.new("Save capture",
        parent_window,
        Gtk::FileChooser::ACTION_SAVE,
        nil,
        [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL],
        [Gtk::Stock::SAVE, Gtk::Dialog::RESPONSE_ACCEPT])

        filename = nil
        filename = dialog.filename if dialog.run == Gtk::Dialog::RESPONSE_ACCEPT
        dialog.destroy

        @capcontrol.save(filename) unless filename.nil?
      end

      def load_cap
        catch :cancel do
          clear
          dialog = Gtk::FileChooserDialog.new("Load capture",
          parent_window,
          Gtk::FileChooser::ACTION_OPEN,
          nil,
          [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL],
          [Gtk::Stock::OPEN, Gtk::Dialog::RESPONSE_ACCEPT])

          filename = nil
          filename = dialog.filename if dialog.run == Gtk::Dialog::RESPONSE_ACCEPT
          dialog.destroy

          @capcontrol.load(filename) unless filename.nil?
        end
      end

      protected
      # Add a detector page for the given detector class (this should be
      # a subclass of AttackDetector). If the detector has parameters, the
      # user will be asked for them at this point.
      def add_detector_page(detector_class)
        tree = PacketTree.new
        catch :cancel do
          begin
            detector = detector_class.new do |pkt|
              page_notify tree, true
              tree.add_packet pkt
            end

            detector.set_revoke do |pkt|
              tree.remove(pkt)
              page_notify(tree,1)
            end
            tree.group_by { |pkt1,pkt2| detector.group? pkt1, pkt2 }

            tree.title = detector.label

            tablabel = TabLabel.new(tree.title) do
              @notebook.remove tree
              @detectors.delete detector
            end

            @notebook.append_page tree, tablabel

            @notebook.show_all

            @detectors << detector
          rescue
            dialog = Gtk::MessageDialog.new nil,
            Gtk::Dialog::MODAL | Gtk::Dialog::DESTROY_WITH_PARENT,
            Gtk::MessageDialog::ERROR, Gtk::MessageDialog::BUTTONS_OK,
            $!
            dialog.run
            dialog.destroy
          end
        end
      end

      def toggle_capture_option(option)
        options = @capcontrol.dnscapture.validate_dns

        options[option] = !options[option]
        if [:check_structure, :check_by_port].include? option and
          !options[:check_structure] and !options[:check_by_port]
          dialog = Gtk::MessageDialog.new nil,
          Gtk::Dialog::MODAL | Gtk::Dialog::DESTROY_WITH_PARENT,
          Gtk::MessageDialog::WARNING, Gtk::MessageDialog::BUTTONS_CLOSE,
          "You have disabled both port checking and structure checking. " +
          "This means that FatNS will analye all traffic going through " +
          "this machine, which could cause great CPU stress and might even " +
          "cause it to 'hang'. Don't do this if you are running FatNS over " +
          "a remote X connection or something similar, as it will cause a " +
          "feedback loop."
          dialog.run
          dialog.destroy
        end
        if option == :check_structure and options[:check_structure]
          dialog = Gtk::MessageDialog.new nil,
          Gtk::Dialog::MODAL | Gtk::Dialog::DESTROY_WITH_PARENT,
          Gtk::MessageDialog::WARNING, Gtk::MessageDialog::BUTTONS_CLOSE,
          "You have enabled structure checking - now only packets which " +
          "match DNS structure will be analyzed. This means that attacks " +
          "based on malformed DNS packets will not be detected."
          dialog.run
          dialog.destroy
        end
        if [:only_udp,:only_tcp].include? option and 
           options[:only_udp] and options[:only_tcp]
          dialog = Gtk::MessageDialog.new nil,
          Gtk::Dialog::MODAL | Gtk::Dialog::DESTROY_WITH_PARENT,
          Gtk::MessageDialog::WARNING, Gtk::MessageDialog::BUTTONS_CLOSE,
          "The intersection between TCP only and UDP only is empty."
          dialog.run
          dialog.destroy
        end
      end

      # Create the GUI menus
      def create_menu
        accel_group = Gtk::AccelGroup.new
        add_accel_group(accel_group)

        menu_factory = Gtk::ItemFactory.new(Gtk::ItemFactory::TYPE_MENU_BAR,
        "<main>", accel_group)

        menu_items = [
        ["/_File"],
        ["/_File/_Clear", "<StockItem>", nil,
        Gtk::Stock::CLEAR, proc { catch(:cancel) { clear } } ],
        ["/_File/_Save Capture", "<StockItem>", nil,
        Gtk::Stock::SAVE, proc { save_cap } ],
        ["/_File/_Load Capture", "<StockItem>", nil,
        Gtk::Stock::OPEN, proc { load_cap } ],

        ["/_File/Separator", "<Separator>", nil, nil, nil],

        ["/_File/_Quit", "<StockItem>", "<control>Q",
        Gtk::Stock::QUIT, proc { quit } ],

        ["/_Attack detectors"],
        ["/_Capture"],
        # Capture option togglers go here
        ["/_Capture/Separator", "<Separator>", nil, nil, nil],
        ["/_Capture/_YAMLize current packet", "<Item>", nil, nil,
          proc { @notebook.get_nth_page(@notebook.page).yaml_popup } ]
        ]

        menu_items.concat AttackDetection.get_detectors.collect { |ad|
          ["/_Attack detectors/#{ad::Name}", "<Item>", nil, nil,
           proc { add_detector_page ad }]
        }


        menu_factory.create_items(menu_items)

        OptionTogglers.keys.each do |k|
          OptionTogglers[k].active = @capcontrol.dnscapture.validate_dns[k]
        end

        capture_menu = menu_factory.get_widget('/Capture')
        OptionTogglers.keys.each do |k|
          OptionTogglers[k].signal_connect('activate') do
            toggle_capture_option k
          end
          capture_menu.prepend OptionTogglers[k]
        end

        menu_factory.get_widget '<main>'
      end
    end
  end
end

