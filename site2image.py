#!/usr/bin/env python
# -*- coding: utf8 -*-
__author__ = 'Robin Wittler <real@the-real.org>'
__version__ = '0.1.3'
__licence__ = 'BSD'

import os
import re
import sys
import pygtk
pygtk.require('2.0')
import gtk
import signal
import webkit
import locale
import datetime
import logging
import logging.handlers
from random import randint
from optparse import OptionParser
from robotparser import RobotFileParser
from ConfigParser import SafeConfigParser


RE_TOPLEVEL_WWW_DIR = '^((http|https)://[^/]+)'
CRE_TOPLEVEL_WWW_DIR = re.compile(RE_TOPLEVEL_WWW_DIR)
RE_SHORT_URL = '^(?:http://|https://)([^/]+)'
CRE_SHORT_URL = re.compile(RE_SHORT_URL)


logger = logging.getLogger(sys.argv[0])
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
        '%(asctime)s %(name)s[%(process)d] ' +
        '%(levelname)s: %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

class BrowserWindow(gtk.Window):
    def __init__(
            self,
            enable_scripts=False,
            enable_java_applet=False,
            enable_private_browsing=False,
            encoding=locale.getdefaultlocale()[-1],
            enable_plugins=False,
            useragent=webkit.WebSettings().get_property('user-agent'),
            enable_file_access_from_file_uris=False,
            timeout=10,
            time_format='%Y%m%d-%H%M%S.%s',
            dirname='/tmp',
            file_prefix='site2image',
            honor_robots_txt=True,
    ):
        gtk.Window.__init__(self, gtk.WINDOW_TOPLEVEL)
        self.set_decorated(False)
        self.fullscreen()
        self.browser = webkit.WebView()
        self.settings = webkit.WebSettings()
        self.settings.set_property('enable-scripts', enable_scripts)
        self.settings.set_property('enable-java-applet', enable_java_applet)
        self.settings.set_property(
                'enable-private-browsing',
                enable_private_browsing
        )
        self.settings.set_property('default-encoding', encoding)
        self.settings.set_property('enable-plugins', enable_plugins)
        self.settings.set_property('user-agent', useragent)
        self.settings.set_property(
                'enable-file-access-from-file-uris',
                enable_file_access_from_file_uris
        )
        self.timeout = int(timeout)
        self.time_format = time_format
        self.dirname = dirname
        self.file_prefix = file_prefix
        self.honor_robots_txt = honor_robots_txt
        self.add(self.browser)
        self.show_all()
        signal.signal(signal.SIGALRM, self.loadTimeout)
        self.urls = list()
        self.last_url = str()
        self.robots_parser = RobotFileParser()
        self.connect('delete_event', self.deleteEvent)
        self.connect('destroy', self.destroyEvent)

    def loadFinished(self, webview, frame):
        logger.info(
                'Finished loading url: %s'
                %(self.last_url)
        )
        self.printWebsite()

    def printWebsite(self):
        # maybe called by timeout so we have to disconnect the events
        # to prevent double calling.
        self.browser.disconnect(self.load_finished_event)
        self.browser.disconnect(self.load_started_event)
        signal.alarm(0)

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
        short_url = CRE_SHORT_URL.match(self.last_url).groups()[0]
        if pixbuffer != None:
            path = os.path.join(
                        self.dirname,
                        self.file_prefix + '-' +
                        short_url + '-' +
                        datetime.datetime.now().strftime(self.time_format) +
                        '-' + str(randint(100000, 999999)) +
                        '.png'
            )
            logger.info('save image of url %s to %s' %(self.last_url, path))
            pixbuffer.save(path, 'png')
            logger.debug('image successfully saved to %s' %(path))
        else:
            logger.critical(
                    'could not take snapshot for url %s'
                    %(self.last_url)
            )
        # calling browser.stop_loading ends up with
        # sending a SIGINT - so this is awefully not what
        # we want. To prevent missleading behavior we
        # load a empty page.
        self.browser.open('about:')
        self.run()

    def addUrls(self, *urls):
        logger.debug(
                'adding urls to class: %s' %(','.join(urls))
        )
        self.urls.extend(urls)

    def checkRobotTXT(self, url):
        match = CRE_TOPLEVEL_WWW_DIR.match(url)
        if match:
            robots_url = match.groups()[0] + '/robots.txt'
            self.robots_parser.set_url(robots_url)
            try:
                self.robots_parser.read()
            except IOError, error:
                if error.errno == 'socket error':
                    logger.exception(error)
                    self.run()
                else:
                    raise
        else:
            logger.info(
                    '%s is not a valid url.' %(url)
            )
            self.run()
        useragent = self.settings.get_property('user-agent')
        if not self.robots_parser.can_fetch(useragent, url):
            logger.debug(
                    'useragnt %s is not allowed to fetch %s.' %(url, useragent)
            )
            self.run()
        else:
            logger.debug(
                    'useragent %s is allowed to fetch %s' %(useragent, url)
            )

    def load(self, url):
        logger.debug(
                'connecting browser to load-finished event'
        )
        self.load_finished_event = self.browser.connect(
                'load-finished',
                self.loadFinished
        )
        logger.debug(
                'connecting browser to load-started event'
        )
        self.load_started_event = self.browser.connect(
                'load-started',
                self.loadStarted
        )
        logger.info('loading url: %s' %(url))
        self.browser.open(url)

    def loadStarted(self, webview, frame):
        logger.debug(
                'load of site %s started. setting timer to %s seconds.'
                %(self.last_url, self.timeout)
        )
        signal.alarm(self.timeout)

    def loadTimeout(self, signum, frame):
        logger.info(
                'Timeout after %s seconds happend while loading url: %s.'
                %(self.timeout, self.last_url)
        )
        self.printWebsite()

    def deleteEvent(self, widget, event, data=None):
        return False

    def destroyEvent(self, widget, data=None):
        logger.debug('exiting now!')
        gtk.main_quit()
        sys.exit(0)

    def run(self):
        if self.urls:
            url = self.urls.pop(0)
            self.last_url = url
            if self.honor_robots_txt:
                self.checkRobotTXT(url)
            self.load(url)
        else:
            logger.info('No more urls to load.')
            self.emit('destroy')


if __name__ == '__main__':
    prog = os.path.basename(sys.argv[0])
    usage = (
            '%s: [--version] [-h|--help] [--enable-scripts] ' +
            '[--enable-java-applet] [--enable-private-browsing] ' +
            '[--set-encoding ENCODING] [--enable-plugins] ' +
            '[--set-useragent AGENT] [--enable-file-access-from-file-uris] ' +
            '[--timeout TIMEOUT] [--time-format FORMAT] [--dir DIR] ' +
            '[--file-prefix PREFIX] [--http-proxy|--https-proxy ADDR] ' +
            '[--proxy-credentials PATH] [--debug LEVEL] ' +
            '[--ignore-robots-txt] URLs'
    ) %(prog)
    parser = OptionParser(usage=usage, version='%s %s' %(prog, __version__))
    parser.add_option(
            '--enable-scripts',
            dest='enable_scripts',
            default=False,
            action='store_true',
            help='Enable embedded scripting languages. [Default: %default]'
    )
    parser.add_option(
            '--enable-java-applet',
            dest='enable_java_applet',
            default=False,
            action='store_true',
            help='Enable Java Applet Support. [Default: %default]'
    )
    parser.add_option(
            '--enable-private-browsing',
            dest='enable_private_browsing',
            default=False,
            action='store_true',
            help='Enable private browsing mode. [Default: %default]'
    )
    parser.add_option(
            '--set-encoding',
            dest='encoding',
            default=locale.getdefaultlocale()[-1],
            metavar='ENCODING',
            help='Set the encoding used to display text. [Default: %default]'
    )
    parser.add_option(
            '--enable-plugins',
            dest='enable_plugins',
            default=False,
            action='store_true',
            help='Set this to enable plugins. [Default: %default]'
    )
    parser.add_option(
            '--set-useragent',
            dest='useragent',
            metavar='AGENT',
            default=webkit.WebSettings().get_property('user-agent'),
            help='Set the Useragent String. [Default: %default]'
    )
    parser.add_option(
            '--enable-file-access-from-file-uris',
            dest='enable_file_access_from_file_uris',
            default=False,
            action='store_true',
            help='Set this to allow file uris. [Default: %default]'
    )
    parser.add_option(
            '--timeout',
            dest='timeout',
            default=10,
            type='int',
            metavar='TIMEOUT',
            help='Set the Timeout for loading URLs. [Default: %default]'
    )
    parser.add_option(
            '--time-format',
            dest='time_format',
            default='%Y%m%d-%H%M%S.%s',
            metavar='FORMAT',
            help='Use this to set the time format applied to filename. [Default: %default]'
    )
    parser.add_option(
            '--dir',
            dest='dirname',
            metavar='DIR',
            default='/tmp',
            help=(
                'Set this to the dir where websites should be saved. ' +
                '[Default: %default]'
            )
    )
    parser.add_option(
            '--file-prefix',
            dest='file_prefix',
            metavar='PREFIX',
            default='site2image',
            help='Set this as a prefix of the filename. [Default: %default]'
    )
    parser.add_option(
            '--http-proxy',
            dest='http_proxy',
            metavar='PROXY_ADDR',
            default=None,
            help='Set this if you use a http proxy. [Default: %default]'
    )
    parser.add_option(
            '--https-proxy',
            dest='https_proxy',
            metavar='PROXY_ADDR',
            default=None,
            help='Set this if you use a https proxy. [Default: %default]'
    )
    parser.add_option(
            '--proxy-credentials',
            dest='proxy_credentials',
            metavar='PATH',
            default=None,
            help=(
                'Set the path to the http(s) proxy credentials. ' +
                '[Default: %default]'
            )
    )
    parser.add_option(
            '--debug',
            dest='debug',
            default='NOTSET',
            metavar='LEVEL',
            help=(
                'Set this to see some messages. Possible Values are: ' +
                'NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL ' +
                '[Default: %default]'
            )
    )
    parser.add_option(
            '--ignore-robots-txt',
            dest='robots_txt',
            action='store_false',
            default=True,
            help=(
                'Set this to deactivate honoring sites robots.txt. ' +
                '[Default: honor robots.txt]'
            )
    )
    (options, args) = parser.parse_args()
    options.debug = options.debug.upper()
    if options.debug not in logging.__dict__:
        sys.stderr.write( 
                '\nError: %s is not a valid debug value\n' %(options.debug)
        )
        parser.print_help()
        sys.exit(0)
    loglevel = getattr(logging, options.debug)
    logger.setLevel(loglevel)
    handler.setLevel(loglevel)
    if not args:
        sys.stderr.write(
                'You must give at least one url.\n'
        )
        sys.exit(0)

    if options.proxy_credentials:
        config_parser = SafeConfigParser()
        if not config_parser.read(options.proxy_credentials):
            sys.stderr.write(
                    'Could not read proxy credentials @ %s\n' \
                    %(options.proxy_credentials)
            )
            sys.exit(0)
        if not config_parser.has_section('proxy_auth'):
            sys.stderr.write(
                    'could not found section \'proxy_auth\' in credentials\n'
            )
            sys.exit(0)
        if not config_parser.has_option('proxy_auth', 'username'):
            sys.stderr.write(
                    'could not found option username in credentials\n'
            )
            sys.exit(0)
        else:
            options.proxy_user = config_parser.get('proxy_auth', 'username')
        if not config_parser.has_option('proxy_auth', 'password'):
            sys.stderr.write(
                    'could not found option password in credentials\n'
            )
            sys.exit(0)
        else:
            options.proxy_password = config_parser.get(
                    'proxy_auth',
                    'password'
            )
    else:
        options.proxy_username = str()
        options.proxy_password = str()

    if options.http_proxy:
        if options.proxy_credentials:
            os.environ['http_proxy'] = 'http://%s:%s@%s' %(
                    options.proxy_username,
                    options.proxy_password,
                    options.http_proxy
            )
        else:
            os.environ['http_proxy'] = 'http://%s' %(options.http_proxy)
    if options.https_proxy:
        if options.proxy_credentials:
            os.environ['https_proxy'] = 'http://%s:%s@%s' %(
                    options.proxy_username,
                    options.proxy_password,
                    options.http_proxy
            )
        else:
            os.environ['https_proxy'] = 'https://%s' %(options.https_proxy)
    urls = list()
    for url in args:
        if not (url.startswith('http://') or url.startswith('https://')):
            urls.append('http://' + url)
    browser = BrowserWindow(
            enable_scripts=options.enable_scripts,
            enable_java_applet=options.enable_java_applet,
            enable_private_browsing=options.enable_private_browsing,
            encoding=options.encoding,
            enable_plugins=options.enable_plugins,
            useragent=options.useragent,
            enable_file_access_from_file_uris=\
                    options.enable_file_access_from_file_uris,
            timeout=options.timeout,
            time_format=options.time_format,
            dirname=options.dirname,
            file_prefix=options.file_prefix,
            honor_robots_txt=options.robots_txt,
    )
    browser.addUrls(*urls)
    browser.run()
    try:
        gtk.main()
    except KeyboardInterrupt:
        browser.emit('delete_event', gtk.gdk.Event(gtk.gdk.NOTHING))
