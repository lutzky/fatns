#!/usr/bin/env ruby

require 'yaml'
require 'gtkhtml2'

module FatNS
  module GUI

    # Visual representation of a collection of DNS packets. They are
    # grouped by query_id, with the first seen question being the
    # root of each group.
    class PacketTree < Gtk::VPaned
      # Font for displaying monospaced description of the packet.
      MONOSPACE_FONT = Pango::FontDescription.new("Terminus,Monospace")

      # Title for this packet tree, used in the GUI tabs
      attr_accessor :title

      # Clear all packets from this tree
      def clear
        @treemodel.clear
      end

      def initialize
        super
        @group_proc = proc { false } # Don't group packets at all by default
        set_size_request(500,200)
        init_tree_model
        init_tree_view
        init_text_view
        make_scroll_panes
      end

      # Remove the specified packet from this tree
      def remove(packet)
        iter = @treemodel.iter_first
        return nil if iter.nil?

        begin
          if iter[5] == packet
            @treemodel.remove(iter)
            return
          end
        end while iter.next!
      end

      # Change the grouping method. The block passed to this function should
      # return +true+ if <tt>pkt1</tt> and <tt>pkt2</tt> are to be grouped
      # together.
      def group_by(&group_proc) # :yields: pkt1, pkt2
        @group_proc = group_proc
      end

      # Add a packet to the tree
      def add_packet(packet)
        query = @treemodel.append(iterator_for(packet))

        query[0] = "0x" + packet.query_id.to_s(16)
        query[1] = packet.from.to_s
        query[2] = packet.to.to_s
        query[3] = packet.is_answer? ? "Answer" : "Question"
        query[4] = packet.summary
        query[5] = packet
      end

      # Show the current packet, YAMLized, in a popup
      def yaml_popup
        return if @treeview.selection.selected.nil?

        packet_yaml = [ @treeview.selection.selected[5] ].to_yaml

        dlg = Gtk::Dialog.new('YAMLized packet', nil,
          Gtk::Dialog::DESTROY_WITH_PARENT,
          [Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_CLOSE],
          [Gtk::Stock::COPY, Gtk::Dialog::RESPONSE_YES]
        )

        buffer = Gtk::TextBuffer.new
        buffer.text = packet_yaml
        textview = Gtk::TextView.new buffer
        textview.editable = false
        textview.modify_font(MONOSPACE_FONT)
        textscroll = Gtk::ScrolledWindow.new nil,nil
        textscroll.set_policy Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC
        textscroll.shadow_type = Gtk::SHADOW_ETCHED_IN
        textscroll.add textview

        dlg.vbox.pack_start textscroll
        dlg.show_all

        if dlg.run == Gtk::Dialog::RESPONSE_YES
          Gtk::Clipboard.get(Gdk::Display.default,
                             Gdk::Selection::CLIPBOARD).text = packet_yaml
        end
        dlg.destroy
      end

      protected
      # Columns displayed in the tree view
      Columns = [ "Query ID", "Source IP", "Destination IP", "Type", "Summary" ]

      def make_scroll_panes
        treescroll = Gtk::ScrolledWindow.new nil,nil
        treescroll.set_policy Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC
        treescroll.add @treeview

        textscroll = Gtk::ScrolledWindow.new nil,nil
        textscroll.set_policy Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC
        textscroll.shadow_type = Gtk::SHADOW_ETCHED_IN
        textscroll.add @textview

        pack1 treescroll, true, true
        pack2 textscroll, true, true
      end

      def init_text_view
        @buffer = Gtk::HtmlDocument.new
        @textview = Gtk::HtmlView.new
        @textview.document = @buffer
      end

      def init_tree_model
        @treemodel = Gtk::TreeStore.new(
        String,            # Query ID
        String,            # Source IP
        String,            # Destination IP
        String,            # Type
        String,            # Summary
        Capture::DnsPacket # Actual packet
        )
      end

      def init_tree_view
        @treeview = Gtk::TreeView.new(@treemodel) 
        @treeview.rules_hint = true
        
        @treeview.enable_search = true
        @treeview.set_search_equal_func do |col, mod, key, iter|
          if iter[5].to_searchstring =~ Regexp.new(key, Regexp::IGNORECASE)
            false
          else
            true
          end
        end

        @link_handler = nil

        @treeview.selection.signal_connect('changed') do |selection|
          if selection.selected
            @buffer.open_stream('text/html')
            @buffer.write_stream selection.selected[5].to_html
            @buffer.write_stream '<br /><a href="#">More details...</a>'
            @buffer.close_stream

            @buffer.signal_handler_disconnect @link_handler if @link_handler
            @link_handler = @buffer.signal_connect('link_clicked') do
              @buffer.open_stream('text/html')
              @buffer.write_stream selection.selected[5].to_long_html
              @buffer.close_stream
            end
          end
        end

        context_menu = Gtk::Menu.new
        to_yaml = Gtk::MenuItem.new('To _YAML')
        to_yaml.signal_connect('activate') { yaml_popup }
        context_menu.append to_yaml
        context_menu.show_all

        @treeview.signal_connect('button_press_event') do |w,e|
          if e.kind_of? Gdk::EventButton and e.button == 3
            context_menu.popup(nil,nil,e.button,e.time)
          end
        end

        @treeview.signal_connect('popup_menu') do
          context_menu.popup(nil,nil,0,Gdk::Event::CURRENT_TIME)
        end

        renderer = Gtk::CellRendererText.new

        Columns.each_with_index do |lbl,i|
          @treeview.append_column(
          Gtk::TreeViewColumn.new(lbl, renderer, {:text => i})
          )
        end
      end

      # Get the appropriate iterator in which a packet should be placed.
      # This uses the given grouping method, as set in group_by.
      def iterator_for(packet)
        iter = @treemodel.iter_first

        return nil if iter.nil?

        found = false
        begin
          if @group_proc.call(iter[5], packet)
            found = true
            break
          end
        end while iter.next!

        iter = nil unless found

        iter
      end
    end
  end
end
