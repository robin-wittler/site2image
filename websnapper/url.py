#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from robotparser import RobotFileParser

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.4.0'

class Url(str):
    '''
    This class represents a URL.
    '''
    PATTERN_URL = (
            '^(?P<protocol>\w+)\:\/\/' +
            '(?P<toplevel>[\.\w\-_]+)' +
            '(?:\:?(?P<port>\d*?))' +
            '(?P<request>\/.*)?$'
    )
    CPATTERN_URL = re.compile(PATTERN_URL)

    class UrlError(Exception):
        '''
        The base UrlError class
        '''
        pass

    def __init__(self, url):
        match = self._parseURL(url)
        self.url = url
        _url_dict = match.groupdict()
        self.protocol = _url_dict.get('protocol')
        self.toplevel = _url_dict.get('toplevel')
        self.request = _url_dict.get('request')
        self.port = _url_dict.get('port')

    def _parseURL(self, url):
        '''
        Parse a Url and check if it is in a valid url form.
        If not it raises an UriError, else return a match object
        '''
        match = self.CPATTERN_URL.match(url)
        if not match:
            raise self.UrlError(
                    '%s does not match any known URI Form.'
                    %(repr(url))
            )
        return match

    def __repr__(self):
        return repr(self.url)

class HttpUrl(Url):
    class HttpUrlError(Url.UrlError):
        '''
        The base HttpUrlError class
        '''
        pass

    def __init__(self, url):
        super(HttpUrl, self).__init__(url)
        if not self.protocol in ('http', 'https'):
            raise self.HttpUrlError(
                    '%s is not a valid http(s) url form'
                    %(repr(url))
            )

class RobotTxtParser(RobotFileParser):
    '''
    This class acts almost like the original RobitFileParser,
    except that it puts robots.txt itself as path to the url.
    So - if you do set_url('http://example.org/foo/bar') it will
    automaticly change that url to 'http://example.org/robots.txt'.
    The original url can be accessed by the orig_url attr.
    '''
    def __init__(self, url=''):
        RobotFileParser.__init__(self, url)

    def set_url(self, url):
        if not url:
            return
        self.orig_url = HttpUrl(url)
        self.host = self.orig_url.toplevel
        self.path = '/robots.txt'
        if self.orig_url.port:
            self.url = (
                    self.orig_url.protocol +
                    '://' +
                    self.host +
                    ':' + self.orig_url.port +
                    self.path
            )
        else:
            self.url = (
                    self.orig_url.protocol +
                    '://' +
                    self.host +
                    self.path
            )


