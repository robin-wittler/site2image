#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.4.0'

import os
from url import HttpUrl
from url import RobotTxtParser
from PyQt4 import QtCore
from PyQt4 import QtGui

class SnapshotApp(object):
    def __init__(self, snapper, config, logger=None):
        self.config = config
        self.snapper = snapper
        self.app = QtGui.QApplication([])
        if not logger:
            from log import NullHandler
            logger = NullHandler()
        self.logger = logger
        self.robotparser = RobotTxtParser()
        self.urls = list()
        if self.config.http_proxy:
            if all((self.config.proxy_user, self.config.proxy_passwd)):
                proxy_url = (
                        '%s:%s@%s:%s'
                        %(
                            self.config.proxy_user,
                            self.config.proxy_passwd,
                            self.config.proxy_host,
                            self.config.proxy_port
                        )
                )
            else:
                proxy_url = (
                        '%s:%s'
                        %(
                            self.config.proxy_host,
                            self.config.proxy_port
                        )
                )
            os.environ['http_proxy'] = 'http://' + proxy_url
            os.environ['https_proxy'] = 'https://' + proxy_url

    def checkRobotsTxt(self, url):
        self.robotparser.set_url(url)
        self.robotparser.read()
        if not self.robotparser.can_fetch(self.config.useragent, url):
            self.logger.debug(
                    'Useragent »%s« is not allowed to fetch %s'
                    %(self.config.useragent, url)
            )
            return False
        self.logger.debug(
                'Useragent »%s« is allowed to fetch %s'
                %(self.config.useragent, url)
        )
        return True

    def setUrls(self, *urls):
        for url in urls:
            url = url.lower()
            if not (
                    url.startswith('http://') or
                    url.startswith('https://')
            ):
                url = 'http://' + url
            try:
                self.urls.append(HttpUrl(url))
            except (HttpUrl.HttpUrlError, HttpUrl.UrlError):
                self.logger.info(
                        '%s is not a valid url ... ignoring it.'
                        %(url)
                )
                continue
            else:
                self.logger.debug('Adding %s to urls' %(url))
        return self.urls

    def _snap(self, url):
        if self.config.honor_robots_txt:
            if not self.checkRobotsTxt(url):
                self.exit()
        if self.config.urlpart:
            self.config.urlpart = url.toplevel
        self._snapper = self.snapper(self.config, logger=self.logger)
        self._snapper.connect(
                self._snapper,
                QtCore.SIGNAL('finished()'),
                self.start
        )
        self._snapper.snap(url)

    def start(self, *urls):
        if urls:
            self.setUrls(*urls)
        if self.urls:
            url = self.urls.pop(0)
            self._snap(url)
        else:
            self.logger.info('Exiting now!')
            self.app.quit()

if __name__ == '__main__':
    pass
