module FatNS
  module GUI
    # Das splashenscreenen
    def GUI.splash!
      splash_window = Gtk::Window.new Gtk::Window::POPUP
      splash_window.window_position = Gtk::Window::POS_CENTER_ALWAYS
      splash_image = Gtk::Image.new('gui/splash.jpg')
      splash_window.add splash_image
      splash_window.show_all
    end
  end
end
