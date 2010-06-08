#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.0.2'

class Uri(object):
    import re
    PATTERN_URI = '^(?P<protocol>\w+)\:\/\/(?P<toplevel>.+?)(?P<request>\/.*)?$'
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
        return self._uri
