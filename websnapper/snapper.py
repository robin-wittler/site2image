#!/usr/bin/env python2.6
# -*- coding: utf-8 -*-

import os
import sys
#import logging
from PIL import Image
from page import Page
from time import sleep
from url import HttpUrl
from PyQt4 import QtGui
from PyQt4 import QtCore
from PyQt4 import QtWebKit
from random import randint
from datetime import datetime

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.4.2'

class SnapperConfig(object):
    def __init__(
            self, save_to_dir='/tmp',
            fileprefix=os.path.splitext(sys.argv[0])[0],
            timeout=10, snapshot_delay=0, proxy_host=None,
            proxy_port=None, proxy_user=None, proxy_passwd=None,
            timeformat='%Y%m%d-%H:%M:%S.%s', urlpart=None, use_timestamp=False,
            filesuffix=None, thumbnails=True, thumbnail_height=300,
            thumbnail_width=300, useragent=None,
            javascript_enabled=False, java_enabled=False,
            plugins_enabled=False, privatebrowsing_enabled=True
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_passwd = proxy_passwd
        self.javascript_enabled = javascript_enabled
        self.java_enabled = java_enabled
        self.privatebrowsing_enabled = privatebrowsing_enabled
        self.plugins_enabled = plugins_enabled
        self.useragent = useragent
        self.timeout = int(timeout)
        self.snaphsot_delay = int(snapshot_delay)
        self.timeformat = timeformat
        self.save_to_dir = save_to_dir
        self.fileprefix = fileprefix
        self.urlpart = urlpart
        self.use_timestamp = use_timestamp
        self.filesuffix = filesuffix
        self.thumbnails = thumbnails
        self.thumbnail_height = int(thumbnail_height)
        self.thumbnail_width = int(thumbnail_width)

class Snapper(QtWebKit.QWebView):
    snap_taken = QtCore.pyqtSignal('QtGui.QImage', name='snapTaken')
    snap_saved = QtCore.pyqtSignal('str', name='snapSaved')
    finished = QtCore.pyqtSignal()

    class SnapshotObjectError(Exception):
        pass

    class CallbackError(SnapshotObjectError):
        pass

    class CallbackNotCallable(CallbackError):
        def __init__(self, callback):
            self.callback = callback
            self.msg = '%s is not callable' %(repr(self.callback))

        def __str__(self):
            return self.msg

    def __init__(self, config, logger=None):
        QtWebKit.QWebView.__init__(self)
        self.config = config
        self.timer = QtCore.QTimer()
        if not logger:
            from log import NullHandler
            logger = NullHandler()
        self.logger = logger
        self._preparePage()
        self.connect(
                self,
                QtCore.SIGNAL('snapTaken(QtGui.QImage)'),
                self.saveSnapshot
        )
        self.connect(
                self,
                QtCore.SIGNAL('snapSaved(str)'),
                self.createThumbnail
        )
        self.connect(
                self,
                QtCore.SIGNAL('finished()'),
                self._exit
        )

    def _preparePage(self):
        self.logger.debug('Preparing Page')
        self.setPage(Page(self.config))

    @QtCore.pyqtSlot()
    def _exit(self):
        pass

    def connectLoadStartedEvent(self):
        if not callable(self.loadStarted):
            raise self.CallbackNotCallable(
                    self.loadStarted
            )
        self.logger.debug('Connecting LoadStarted Event')
        self.connect(
                self,
                QtCore.SIGNAL('loadStarted()'),
                self.loadStarted
        )

    def disconnectLoadStartedEvent(self):
        self.logger.debug('Disconnecting LoadStarted Event')
        self.disconnect(
                self,
                QtCore.SIGNAL('loadStarted()'),
                self.loadStarted
        )

    def connectLoadFinishedEvent(self):
        if not callable(self.loadFinished):
            raise self.CallbackNotCallable(
                    self.loadFinished
            )
        self.logger.debug('Connecting LoadFinished Event')
        self.connect(
                self,
                QtCore.SIGNAL('loadFinished(bool)'),
                self.loadFinished
        )

    def disconnectLoadFinishedEvent(self):
        self.logger.debug('Disconnecting LoadFinished Event')
        self.disconnect(
                self,
                QtCore.SIGNAL('loadFinished(bool)'),
                self.loadFinished
        )

    def connectLoadTimeoutEvent(self):
        if not callable(self.loadTimeout):
            raise self.CallbackNotCallable(
                    self.loadTimeout
            )
        self.logger.debug('Connecting LoadTimeout Event')
        self.connect(
                self.timer,
                QtCore.SIGNAL('timeout()'),
                self.loadTimeout
        )

    def disconnectLoadTimeoutEvent(self):
        self.logger.debug('Disconnecting LoadTimeout Event')
        self.disconnect(
                self.timer,
                QtCore.SIGNAL('timeout()'),
                self.loadTimeout
        )

    def connectLoadEvents(self):
        self.connectLoadFinishedEvent()
        self.connectLoadStartedEvent()
        self.connectLoadTimeoutEvent()

    def disconnectLoadEvents(self):
        self.disconnectLoadFinishedEvent()
        self.disconnectLoadStartedEvent()
        self.disconnectLoadTimeoutEvent()

    def loadStarted(self):
        self.logger.info('Starting load of url %s' %(self.url))
        self.timer.start(self.config.timeout * 1000)
        self.logger.debug('Timer started.')

    def loadTimeout(self):
        self.logger.info(
                'Timeout while loading url %s' %(self.url)
        )
        self.timer.stop()
        self.logger.debug('Timer stopped.')
        self.disconnectLoadEvents()
        self.takeSnapshot()

    def loadFinished(self):
        self.logger.info('Load of url %s finished.' %(self.url))
        self.timer.stop()
        self.logger.debug('Timer stopped.')
        self.disconnectLoadEvents()
        self.takeSnapshot()

    def createTimestamp(self, timeformat=None):
        timeformat = timeformat or self.config.timeformat
        if not timeformat:
            raise SnapshotObjectError('No timeformat set')
        return datetime.now().strftime(timeformat)

    def createPathName(self, dirname, fileprefix, urlpart=None,
            timestamp=None, filesuffix=None):

        filename = '-'.join(
                filter(lambda x: x, (fileprefix, urlpart, timestamp, filesuffix))
        )
        return os.path.join(dirname, filename)

    @QtCore.pyqtSlot()
    def takeSnapshot(self):
        #sometimes the painter engine is not ready - for whatever reasons ;)
        #so hopefully adding a nap could "fix" this
        if self.config.snapshot_delay:
            sleep(self.config.snapshot_delay)
        self.page().setViewportSize(
                self.page().mainFrame().contentsSize()
        )
        image = QtGui.QImage(
                self.page().viewportSize(),
                QtGui.QImage.Format_ARGB32
        )
        painter = QtGui.QPainter(image)
        self.page().mainFrame().render(painter)
        painter.end()
        self.logger.debug('Snapshot for url %s taken.' %(self.url))
        self.snap_taken.emit(image)

    @QtCore.pyqtSlot()
    def saveSnapshot(self, image):
        if self.config.use_timestamp:
            timestamp = self.createTimestamp()
        else:
            timestamp = None
        if self.config.filesuffix.lower() == 'random':
            filesuffix = create_random_ints()
        else:
            filesuffix = self.config.filesuffix
        path = self.createPathName(
                self.config.save_to_dir, self.config.fileprefix,
                self.config.urlpart, timestamp, filesuffix
        )
        fullpath = path + '.png'
        image.save(fullpath)
        self.logger.debug(
                'Snapshot of url %s saved to %s.' %(self.url, fullpath)
        )
        self.snap_saved.emit(fullpath)

    @QtCore.pyqtSlot()
    def createThumbnail(self, path):
        if self.config.thumbnails:
            image = Image.open(path)
            width = self.config.thumbnail_width
            height = self.config.thumbnail_height
            image.thumbnail((width, height), Image.ANTIALIAS)
            fullpath = (
                    os.path.splitext(path)[0] + '-thumbnail.png'
            )
            image.save(fullpath, 'PNG')
            self.logger.debug(
                    'Thumbnail of url %s saved to %s'
                    %(self.url, fullpath)
            )
        self.finished.emit()

    def snap(self, url):
        self.url = HttpUrl(url)
        self.connectLoadEvents()
        self.load(QtCore.QUrl(self.url))
        return

def create_random_ints( start=100000, stop=999999):
    return str(randint(start, stop))
