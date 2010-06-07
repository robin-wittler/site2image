#!/usr/bin/env python
# -*- coding: utf8 -*-

import pygtk
pygtk.require('2.0')
import gtk
import os
import sys
import gobject
import datetime
from uritool import Uri
from random import randint
from lib.logtool import logger
from robotparser import RobotFileParser


__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.1.0'

class GtkSnapshotApplication(object):
    class Error(Exception):
        pass

    class GtkSnapshotApplicationError(Error):
        pass

    def __init__(self, window, browser, options):
        self.window = window()
        self.browser = browser(
                enable_scripts=options.enable_scripts,
                enable_java_applet=options.enable_java_applet,
                enable_private_browsing=options.enable_private_browsing,
                default_encoding=options.default_encoding,
                enable_plugins=options.enable_plugins,
                user_agent=options.user_agent,
                enable_file_access_from_file_uris=\
                        options.enable_file_access_from_file_uris
        )
        self.uri = None
        self.dirname = options.dirname
        self.time_format = options.time_format
        self.file_prefix = options.file_prefix
        self.timeout = options.timeout
        self.honor_robots_txt = options.honor_robots_txt
        self.robotsparser = RobotFileParser()
        self.timeout_accured = False
        self.timer = None

    def addUri(self, uri):
        self.uri = Uri(uri)
        return True

    def _checkSetUri(self):
        if not self.uri:
            raise self.GtkSnapshotApplicationError(
                    'you must first call addUri method'
            )
        return True

    def checkRobotsTXT(self):
        self._checkSetUri()
        if self.uri.protocol in ('http', 'https'):
            robots_uri = (
                    self.uri.protocol + '://' +
                    self.uri.toplevel + '/robots.txt'
            )
            self.robotsparser.set_url(robots_uri)
            self.robotsparser.read()
            if self.robotsparser.can_fetch(
                    self.browser.settings.user_agent,
                    self.uri.asStr()
            ):
                logger.debug(
                        'useragent %s is allowed to fetch %s'
                        %(self.browser.settings.user_agent, self.uri.asStr())
                )
                return True
            else:
                logger.debug(
                        'useragent %s is not allowed to fetch %s'
                        %(self.browser.settings.user_agent, self.uri.asStr())
                )
        else:
            logger.debug(
                    '%s is not a http(s) uri'
                    %(self.uri.asStr())
            )
        return False

    def load(self):
        self._checkSetUri()
        if self.honor_robots_txt:
            if not self.checkRobotsTXT():
                return False
        self.load_finished_event_id = self.browser.connect(
                'load-finished',
                self.loadFinished
        )
        self.load_started_event_id =  self.browser.connect(
                'load-started',
                self.loadStarted
        )
        logger.info(
                'loading url: %s' %(self.uri.asStr())
        )
        self.browser.open(self.uri.asStr())

    def timeoutAccured(self):
        if self.timeout_accured:
            return False
        logger.debug(
                'timeout after %s seconds reached. ' %(self.timeout)
        )
        self.timeout_accured = True
        self.takeSnapshot()

    def loadFinished(self, widget, frame):
        self.takeSnapshot()
        return True

    def loadStarted(self, widget, frame):
        logger.debug(
                'load-started event received'
        )
        logger.debug(
                'starting timer for timeout'
        )
        self.timer = gobject.timeout_add_seconds(self.timeout, self.timeoutAccured)
        return True

    def takeSnapshot(self):
         self._checkSetUri()
         gobject.source_remove(self.timer)
         self.browser.disconnect(self.load_finished_event_id)
         self.browser.disconnect(self.load_started_event_id)
         snapshot = self.browser.get_snapshot()
         snapshot_size = snapshot.get_size()
         pixbuffer = gtk.gdk.Pixbuf(
                 gtk.gdk.COLORSPACE_RGB,
                 False,
                 8,
                 *snapshot_size
         )
         pixbuffer = pixbuffer.get_from_drawable(
                 snapshot,
                 snapshot.get_colormap(),
                 0,
                 0,
                 0,
                 0,
                 *snapshot_size
         )
         if pixbuffer != None:
             logger.debug(
                     'snapshot for url: %s taken'
                     %(self.uri.asStr())
             )
             path = os.path.join(
                     self.dirname,
                     self.file_prefix + '-' +
                     self.uri.toplevel + '-' +
                     '%sx%s' %(snapshot_size) + '-' +
                     datetime.datetime.now().strftime(self.time_format) + '-' +
                     str(randint(100000, 999999)) +
                     '.png'
             )
             pixbuffer.save(path, 'png')
             logger.debug(
                     'snapshot successfully saved to %s' %(path)
             )
         else:
             logger.debug(
                     'no snapshot for url: %s taken' %(self.uri.asStr())
              )
         self.browser.open('about:')
         self.info(
                 'all actions for url: %s done' %(self.uri.asStr())
         )
         gtk.main_quit()
         return

    def start(self):
        self._checkSetUri()
        self.window.add(self.browser)
        self.window.show_all()
        self.load()
        gtk.main()
        return True
