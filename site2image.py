#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import locale
import logging


#with pyside i got segmentation faults :(
#if you wanne test it, just comment out all
#pyside imports and comment in all PyQt4 imports
#happy segfault! ;)
#from PySide import QtCore
#from PySide import QtGui
#from PySide import QtWebKit
#from PySide import QtNetwork

from PyQt4 import QtGui
from PyQt4 import QtCore
from PyQt4 import QtWebKit
from PyQt4 import QtNetwork

from PIL import Image
from time import sleep
from random import randint
from datetime import datetime
from optparse import OptionParser
from robotparser import RobotFileParser
from ConfigParser import SafeConfigParser

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


__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.2.0'

class Uri(str):
    PATTERN_URI = '^(?P<protocol>\w+)\:\/\/(?P<toplevel>[\.\w\-_]+?)(?P<request>\/.*)?$'
    CPATTERN_URI = re.compile(PATTERN_URI)

    class Error(Exception):
        pass

    class UriError(Error):
        pass

    def __init__(self, uri):
        self._uri_match = self.parseURI(uri)
        self._uri = uri
        self._uri_dict = self._uri_match.groupdict()
        self.protocol = self._uri_dict.get('protocol')
        self.toplevel = self._uri_dict.get('toplevel')
        self.request = self._uri_dict.get('request')

    def parseURI(self, uri):
        match = self.CPATTERN_URI.match(uri)
        if not match:
            raise self.UriError(
                    '%s does not match any known URI Form.'
                    %(repr(uri))
            )
        return match

    def asStr(self):
        return self._uri

    def __repr__(self):
        return repr(self._uri)


class HttpUri(Uri):
    class HttpUriError(Uri.UriError):
        pass

    def __init__(self, uri):
        super(HttpUri, self).__init__(uri)
        if not self.protocol in ('http', 'https'):
            raise self.HtppUriError(
                    '%s is not a valid http(s) uri form'
                    %(repr(uri))
            )


class HttpProxySettings(QtNetwork.QNetworkAccessManager):
    def __init__(self, host, port, user=None, passwd=None):
        QtNetwork.QNetworkAccessManager.__init__(self)
        self._proxy = self.proxy()
        self._proxy.setHostName(host)
        self._proxy.setPort(port)
        if user:
            self._proxy.setUser(user)
        if passwd:
            self._proxy.setPassword(passwd)
        self._proxy.setType(self._proxy.HttpProxy)
        self.setProxy(self._proxy)


class Page(QtWebKit.QWebPage):
    def __init__(self, useragent=None, proxy=None, **kargs):
        QtWebKit.QWebPage.__init__(self)
        if useragent:
            self.useragent = QtCore.QString(useragent)
            self.userAgentForUrl = lambda s: self.useragent

        self.mainFrame().setScrollBarPolicy(
                QtCore.Qt.Horizontal,
                QtCore.Qt.ScrollBarAlwaysOff
        )
        self.mainFrame().setScrollBarPolicy(
                QtCore.Qt.Vertical,
                QtCore.Qt.ScrollBarAlwaysOff
        )
        if proxy:
            self.setNetworkAccessManager(proxy)

        self.settings().setAttribute(
                QtWebKit.QWebSettings.JavascriptEnabled,
                kargs.get('JavascriptEnabled', False)
        )
        self.settings().setAttribute(
                QtWebKit.QWebSettings.JavaEnabled,
                kargs.get('JavaEnabled', False)
        )
        self.settings().setAttribute(
                QtWebKit.QWebSettings.PluginsEnabled,
                kargs.get('PluginsEnabled', False)
        )
        self.settings().setAttribute(
                QtWebKit.QWebSettings.PrivateBrowsingEnabled,
                kargs.get('PrivateBrowsingEnabled', True)
        )

class Browser(QtWebKit.QWebView):
    def __init__(self, page):
        QtWebKit.QWebView.__init__(self)
        self.setPage(page)

    def getSite(self, url):
        self.load(QtCore.QUrl(url))


class SnapshotApp(object):
    def __init__(self, qtapp, urls, options):
        self.app = qtapp
        self.urls = urls
        self.options = options
        self.getNetworkSettings()
        self.timer = QtCore.QTimer()
        QtCore.QObject.connect(
                self.timer,
                QtCore.SIGNAL('timeout()'),
                self._loadTimeout
        )
        self.robotsparser = RobotFileParser()

    def getNetworkSettings(self):
        #proxy = None
        if self.options.http_proxy:
            if getattr(self.options, 'http_proxy_user', None):
                self.proxy = HttpProxySettings(
                        self.options.http_proxy_host,
                        int(self.options.http_proxy_port),
                        user=self.options.http_proxy_user,
                        passwd=self.options.http_proxy_passwd
                )
            else:
                self.proxy = HttpProxySettings(
                        self.options.http_proxy_host,
                        int(self.options.http_proxy_port)
                )
        else:
            self.proxy = None
        #return proxy

    def createPage(self, proxy=None):
        return Page(
                useragent=options.user_agent,
                proxy=self.proxy,
                JavascriptEnabled=self.options.enable_scripts,
                JavaEnabled=self.options.enable_java_applet,
                PluginsEnabled=self.options.enable_plugins,
                PrivateBrowingEnabled=self.options.private_browsing
        )

    def _loadStarted(self):
        logger.info(
                'Loading of url %s started' %(self.last_url)
        )
        self.timer.start(self.options.timeout * 1000)

    def _loadTimeout(self):
        self.browser.disconnect(
                self.browser,
                QtCore.SIGNAL('loadFinished(bool)'),
                self._loadFinished
        )
        logger.info(
                'Timeout while loading url %s after %s seconds received'
                %(self.last_url, self.options.timeout)
        )
        self.timer.stop()
        self.takeSnapshot()

    def _loadFinished(self):
        logger.info(
                'Loading url %s is complete' %(self.last_url)
        )
        self.timer.stop()
        self.takeSnapshot()

    def createPathName(self):
        return os.path.join(
                self.options.dirname,
                self.options.file_prefix + '-' +
                self.last_url.toplevel + '-' +
                datetime.now().strftime(self.options.time_format) + '-' +
                str(randint(100000, 999999))
        )


    def takeSnapshot(self):
        #sometimes the painter engine is not ready - for whatever reasons ;)
        #so hopefully adding a nap could "fix" this
        if self.options.snap_delay:
            logger.info(
                    'Taking a %s seconds nap before take the snap ;)'
                    %(self.options.snap_delay)
            )
            sleep(self.options.snap_delay)
        logger.info('Takeing snapshot for url %s' %(self.last_url))
        self.browser.page().setViewportSize(
                self.browser.page().mainFrame().contentsSize()
        )
        image = QtGui.QImage(
                self.browser.page().viewportSize(),
                QtGui.QImage.Format_ARGB32
        )
        painter = QtGui.QPainter(image)
        self.browser.page().mainFrame().render(painter)
        painter.end()
        path = self.createPathName()
        #wtf? the qt crap raises no exception if it couldn't save the file?
        #so we have to proof it manualy :(
        image.save(path + '.png')
        if not os.path.exists(path + '.png'):
            logger.error('Could not save snapshot to %s' %(path + '.png'))
            self.run()
        else:
            logger.debug('Snapshot saved to %s' %(path + '.png'))

        if self.options.thumbnails and self.options.thumbnail_size:
             #the qt own scaler is not cute enough ... we take PIL
             image = Image.open(path + '.png')
             image.thumbnail(
                     (
                         self.options.thumbnail_width,
                         self.options.thumbnail_height
                     ),
                     Image.ANTIALIAS
             )
             image.save(path + '-thumbnail.png', 'PNG')
             logger.debug(
                     'Thumbnail saved to %s' %(path + '-thumbnail.png')
             )

        self.run()

    def checkUrl(self, url):
        try:
            self.last_url = HttpUri(url)
        except HttpUri.HttpUriError:
            logger.info(
                    '%s is not a valid http(s) url'
                    %(repr(url))
            )
            self.run()
        else:
            if options.honor_robots_txt:
                if not self.checkRobotsTXT():
                    self.run()

    def checkRobotsTXT(self):
        robots_url = (
                self.last_url.protocol + '://' +
                self.last_url.toplevel + '/robots.txt'
        )
        self.robotsparser.set_url(robots_url)
        self.robotsparser.read()
        if self.robotsparser.can_fetch(
                self.options.user_agent,
                self.last_url
        ):
                logger.debug(
                        'useragent %s is allowed to fetch %s'
                        %(self.options.user_agent, self.last_url)
                )
                return True
        else:
            logger.debug(
                    'useragent %s is not allowed to fetch %s'
                    %(self.optionss.user_agent, self.last_url)
            )
            return False

    def run(self):
        if self.urls:
            self.checkUrl(self.urls.pop(0))
            page = self.createPage()
            self.browser = Browser(page)
            self.browser.connect(
                    self.browser,
                    QtCore.SIGNAL('loadStarted()'),
                    self._loadStarted
            )
            self.browser.connect(
                    self.browser,
                    QtCore.SIGNAL('loadFinished(bool)'),
                    self._loadFinished
            )
            self.browser.getSite(self.last_url)
        else:
            logger.info('No more url to load.')
            self.app.quit()

def cmdline_parse(version=None):
    prog = os.path.basename(sys.argv[0])
    usage = (
            '%s: [--version] [-h|--help] [--enable-scripts] ' +
            '[--enable-java-applet] [--enable-private-browsing] ' +
            '[--enable-plugins] ' +
            '[--set-useragent AGENT] ' +
            '[--timeout TIMEOUT] [--time-format FORMAT] [--dir DIR] ' +
            '[--file-prefix PREFIX] [--http-proxy ADDR] ' +
            '[--proxy-credentials PATH] [--debug LEVEL] ' +
            '[--ignore-robots-txt] [--thumbnail-size SIZE] ' +
            '[--disable-thumbnails] [--snap-delay SECONDS] URLs'
    ) %(prog)
    version = version or __version__
    parser = OptionParser(usage=usage, version='%s %s' %(prog, version))
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
            '--disable-private-browsing',
            dest='private_browsing',
            default=True,
            action='store_false',
            help='Disable private browsing mode. [Default: enabled]'
    )
#comes with next update, i promise.
#    parser.add_option(
#            '--set-encoding',
#            dest='default_encoding',
#            default=locale.getdefaultlocale()[-1],
#            metavar='ENCODING',
#            help='Set the encoding used to display text. [Default: %default]'
#    )
    parser.add_option(
            '--enable-plugins',
            dest='enable_plugins',
            default=False,
            action='store_true',
            help='Set this to enable plugins. [Default: %default]'
    )
    parser.add_option(
            '--set-useragent',
            dest='user_agent',
            metavar='AGENT',
            default=(
                'site2image - a webkit based websnapper. Version %s.'
                %(version)
            ),
            help='Set the Useragent String. [Default: %default]'
    )
#this setting does not exist in the QtWebKit?
#    parser.add_option(
#            '--enable-file-access-from-file-uris',
#            dest='enable_file_access_from_file_uris',
#            default=False,
#            action='store_true',
#            help='Set this to allow file uris. [Default: %default]'
#    )
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
            help='Set this if you use a http(s) proxy. [Default: %default]'
    )
#    parser.add_option(
#            '--https-proxy',
#            dest='https_proxy',
#            metavar='PROXY_ADDR',
#            default=None,
#            help='Set this if you use a https proxy. [Default: %default]'
#    )
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
            dest='honor_robots_txt',
            action='store_false',
            default=True,
            help=(
                'Set this to deactivate honoring sites robots.txt. ' +
                '[Default: honor robots.txt]'
            )
    )
    parser.add_option(
            '--thumbnail-size',
            dest='thumbnail_size',
            default='150x300',
            metavar='SIZE',
            help='Set the thumbnails size. [Default: %default]'
    )
    parser.add_option(
            '--disable-thumbnails',
            dest='thumbnails',
            default=True,
            action='store_false',
            help='Set this to disable thumbnails. [Default: %default]'
    )
    parser.add_option(
            '--snap-delay',
            dest='snap_delay',
            default=0,
            type='int',
            metavar='SECONDS',
            help='Add n seconds for a delayd snapshot. [Default %default]'
    )

    (options, args) = parser.parse_args()
    options.debug = options.debug.upper()
    if options.debug not in logging.__dict__:
        sys.stderr.write(
                '\nError: %s is not a valid debug value\n' %(options.debug)
        )
        parser.print_help()
        sys.exit(0)
    if not args:
        sys.stderr.write(
                'You must give at least one url.\n'
        )
        sys.exit(0)

    if options.proxy_credentials:
        config_parser = SafeConfigParser()
        if not config_parser.read(options.proxy_credentials):
            sys.stderr.write(
                    '%s is not readable or parseable'
                    %(options.proxy_credentials)
            )

    if options.http_proxy:
        options.http_proxy_host, options.http_proxy_port = \
                options.http_proxy.rsplit(':', 1)
        if options.proxy_credentials:
            if not config_parser.has_section('http_proxy_auth'):
                sys.stderr.write(
                        'could not found section \'http_proxy_auth\' ' +
                        'in credentials\n'
                )
                sys.exit(0)
            if not config_parser.has_option('http_proxy_auth','username'):
                sys.stderr.write(
                        'could not found option username ' +
                        'for http_proxy_auth credentials\n'
                )
                sys.exit(0)
            else:
                options.http_proxy_user = config_parser.get(
                        'http_proxy_auth',
                        'username'
                )
            if not config_parser.has_option('http_proxy_auth', 'password'):
                sys.stderr.write(
                        'could not found option password for ' +
                        'http_proxy_auth credentials\n'
                )
                sys.exit(0)
            else:
                options.http_proxy_passwd = config_parser.get(
                        'http_proxy_auth',
                        'password'
                )
            http_proxy = 'http://%s:%s@%s:%s' %(
                    options.http_proxy_user,
                    options.http_proxy_passwd,
                    options.http_proxy_host,
                    options.http_proxy_port
            )
            https_proxy = 'https://%s:%s@%s:%s' %(
                    options.http_proxy_user,
                    options.http_proxy_passwd,
                    options.http_proxy_host,
                    options.http_proxy_port
            )
        else:
            http_proxy = 'http://%s:%s' \
                    %(options.http_proxy_host, options.http_proxy_port)
            https_proxy = 'https://%s:%s' \
                    %(options.http_proxy_host, options.http_proxy_port)
        os.environ['http_proxy'] = http_proxy
        os.environ['https_proxy'] = https_proxy

    urls = list()
    for url in args:
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url
        urls.append(url)

    if options.thumbnail_size:
        try:
            thumbnail_width, thumbnail_height = \
                    options.thumbnail_size.split('x')
        except ValueError:
            sys.stderr.write(
                    'The format for thumbnail size is Width x Height' +
                    '(e.g. 50x50)\n'
            )
            sys.exit(0)
        options.thumbnail_width = int(thumbnail_width.rstrip(' '))
        options.thumbnail_height = int(thumbnail_height.lstrip(' '))

    return options, urls


if __name__ == '__main__':
    options, urls = cmdline_parse()
    logger.setLevel(getattr(logging, options.debug))
    app = QtGui.QApplication([])
    snapper = SnapshotApp(app, urls, options)
    snapper.run()
    sys.exit(app.exec_())
