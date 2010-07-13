#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.4.2'

from PyQt4 import QtCore
from PyQt4 import QtWebKit


class Page(QtWebKit.QWebPage):
    def __init__(self, config):
        QtWebKit.QWebPage.__init__(self)
        self.config = config
        if self.config.useragent:
            self.useragent = QtCore.QString(self.config.useragent)
            self.userAgentForUrl = lambda s: self.useragent

        self.mainFrame().setScrollBarPolicy(
                QtCore.Qt.Horizontal,
                QtCore.Qt.ScrollBarAlwaysOff
        )
        self.mainFrame().setScrollBarPolicy(
                QtCore.Qt.Vertical,
                QtCore.Qt.ScrollBarAlwaysOff
        )

        if all((self.config.proxy_host, self.config.proxy_port)):
            network = self.networkAccessManager()
            proxy = network.proxy()
            proxy.setHostName(self.config.proxy_host)
            proxy.setPort(self.config.proxy_port)
            proxy.setType(proxy.HttpProxy)
            if all((self.config.proxy_user, self.config.proxy_passwd)):
                proxy.setUser(self.config.proxy_user)
                proxy.setPassword(self.config.proxy_passwd)
            network.setProxy(proxy)
            self.setNetworkAccessManager(network)

        self.settings().setAttribute(
                QtWebKit.QWebSettings.JavascriptEnabled,
                self.config.javascript_enabled
        )
        self.settings().setAttribute(
                QtWebKit.QWebSettings.JavaEnabled,
                self.config.java_enabled
        )
        self.settings().setAttribute(
                QtWebKit.QWebSettings.PluginsEnabled,
                self.config.plugins_enabled
        )
        self.settings().setAttribute(
                QtWebKit.QWebSettings.PrivateBrowsingEnabled,
                self.config.privatebrowsing_enabled
        )
