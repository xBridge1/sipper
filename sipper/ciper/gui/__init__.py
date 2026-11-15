def launch_gui(argv=None):
    from ciper.gui.app import launch_gui as _launch_gui

    _launch_gui(argv)


__all__ = ["launch_gui"]
