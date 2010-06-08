#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__version__ = '0.1.5'
__licence__ = 'GPL3'

def Main():
    from lib.cmdtool import cmdline_parse
    options, urls = cmdline_parse(version=__version__)
    import sys
    from lib.uritool import Uri
    from lib.window import Window
    from lib.browser import WebkitWebView
    from lib.logtool import logger, logging, handler
    from lib.application import GtkSnapshotApplication

    logger.setLevel(getattr(logging, options.debug))
    for url in urls:
        try:
            application = GtkSnapshotApplication(Window, WebkitWebView, options)
            application.addUri(url)
            application.start()
        except Exception, error:
            logger.exception(error)
    sys.exit(0)

if __name__ == '__main__':
    Main()

