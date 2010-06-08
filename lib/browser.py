#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__version__ = '0.0.2'
__licence__ = 'GPL3'

import webkit
from logtool import logger

class WebkitWebView(webkit.WebView):
    def __init__(self, **properties):
        webkit.WebView.__init__(self)
        self.settings = self.get_settings().props
        for name, value in properties.iteritems():
            try:
                setattr(self.settings, name, value)
            except Exception, error:
                logger.exception(error)

