#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'Robin Wittler <real@the-real.org>'
__version__ = '0.1.0'
__licence__ = 'GPL3'

import os
import sys
import webkit
import locale
import logging
from optparse import OptionParser
from ConfigParser import SafeConfigParser

def cmdline_parse(version=None):
    prog = os.path.basename(sys.argv[0])
    usage = (
            '%s: [--version] [-h|--help] [--enable-scripts] ' +
            '[--enable-java-applet] [--enable-private-browsing] ' +
            '[--set-encoding ENCODING] [--enable-plugins] ' +
            '[--set-useragent AGENT] [--enable-file-access-from-file-uris] ' +
            '[--timeout TIMEOUT] [--time-format FORMAT] [--dir DIR] ' +
            '[--file-prefix PREFIX] [--http-proxy|--https-proxy ADDR] ' +
            '[--proxy-credentials PATH] [--debug LEVEL] ' +
            '[--ignore-robots-txt] [--thumbnail-size SIZE] ' +
            '[--disable-thumbnails] URLs'
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
            '--enable-private-browsing',
            dest='enable_private_browsing',
            default=False,
            action='store_true',
            help='Enable private browsing mode. [Default: %default]'
    )
    parser.add_option(
            '--set-encoding',
            dest='default_encoding',
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
            dest='user_agent',
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
            default='50x50',
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
                options.http_proxy_password = config_parser.get(
                        'http_proxy_auth',
                        'password'
                )
            http_proxy = 'http://%s:%s@%s' %(
                    options.http_proxy_username,
                    options.http_proxy_password,
                    options.http_proxy
            )
        else:
            http_proxy = 'http://%s' %(options.http_proxy)
        os.environ['http_proxy'] = http_proxy

    if options.https_proxy:
        if options.proxy_credentials:
            if not config_parser.has_section('https_proxy_auth'):
                sys.stderr.write(
                        'could not found section \'https_proxy_auth\' ' +
                        'in credentials\n'
                )
                sys.exit(0)
            if not config_parser.has_option('https_proxy_auth', 'username'):
                sys.stderr.write(
                        'could not found option username ' +
                        'for https_proxy_auth credentials\n'
                )
                sys.exit(0)
            else:
                options.https_proxy_user = config_parser.get(
                        'https_proxy_auth',
                        'username'
                )
            if not config_parser.has_option('https_proxy_auth', 'password'):
                sys.stderr.write(
                        'could not found option password for ' +
                        'https_proxy_auth credentials\n'
                )
                sys.exit(0)
            else:
                options.https_proxy_password = config_parser.get(
                        'https_proxy_auth',
                        'password'
                )
            https_proxy = 'https://%s:%s@%s' %(
                    options.https_proxy_username,
                    options.https_proxy_password,
                    options.https_proxy
            )
        else:
            https_proxy = 'https://%s' %(options.https_proxy)
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
