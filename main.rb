#!/usr/bin/env ruby


require 'gtk2'

Gtk.init
require 'gui/splash'
splash_screen = FatNS::GUI.splash!

timeout = Gtk.timeout_add(10) do
  require 'gui/main_window'
  @window = FatNS::GUI::MainWindow.new
  @window.signal_connect('destroy') { Gtk.main_quit }
  @window.show_all
  splash_screen.destroy
  Gtk.timeout_remove timeout 
end

Gtk.main
