#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.5.3'


import os
import sys
import logging
from optparse import OptionGroup
from optparse import OptionParser
from websnapper.url import HttpUrl
from optparse import SUPPRESS_HELP
from optparse import OptionValueError
from websnapper.log import logformat
from websnapper.log import get_logger
from websnapper.log import set_logging
from websnapper.snapper import Snapper
from websnapper.application import SnapshotApp

def cmdline_parser(version=None, dryrun=False, description='', epilog=''):

    def loglevel_callback(option, opt_str, value, parser):
        value = value.upper()
        choices = ['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if not value in choices:
            raise OptionValueError(
                    '%s is not a valid loglevel. You can only choose from %s'
                    %(value, ', '.join(choices))
            )
        loglevel = getattr(logging, value)
        setattr(parser.values, option.dest, loglevel)

    def proxy_credentials_callback(option, opt_str, value, parser):
        parser.values.proxy_user = None
        parser.values.proxy_passwd = None
        try:
            parser.values.read_file(value)
        except Exception, error:
            raise OptionValueError(error)
        if not all((parser.values.proxy_user, parser.values.proxy_passwd)):
            if not parser.values.proxy_user:
                raise OptionValueError(
                        'No valid credential %s found.' %('proxy_user')
                )
            else:
                raise OptionValueError(
                        'No valid credential %s found.' %('proxy_passwd')
                )

    def http_proxy_callback(option, opt_str, value, parser):
        parser.values.proxy_host = None
        parser.values.proxy_port = None
        parser.values.http_proxy = None
        if not opt_str.startswith('http://') or not opt_str.startswith('https://'):
            value = 'http://' + value
        url = HttpUrl(value)
        if not url.port:
            raise OptionValueError(
                    'No port information found for proxy'
            )
        parser.values.proxy_host = url.toplevel
        parser.values.proxy_port = int(url.port)
        parser.values.http_proxy = url

    prog = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    usage = (
            '%s [--version] [-h|--help] [options] urls'
    ) %(prog)
    description = description or (
            '%s is a QtWebKit based websnapper which ' +
            'load given urls and makes screenshots of them. ' +
            'You will need a running xserver. At least you will ' +
            'need xvfb to make %s run.') %(prog, prog)

    epilog = epilog or '''THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
    APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
    HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
    OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
    IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
    ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
    '''

    version = version or __version__
    parser = OptionParser(
            usage=usage,
            version='%s %s' %(prog, version),
            description=description,
            epilog=epilog
    )
    parser.add_option(
            '--enable-scripts',
            dest='javascript_enabled',
            default=False,
            action='store_true',
            help='Enable embedded scripting languages. [Default: %default]'
    )
    parser.add_option(
            '--enable-java-applet',
            dest='java_enabled',
            default=False,
            action='store_true',
            help='Enable Java Applet Support. [Default: %default]'
    )
    parser.add_option(
            '--disable-private-browsing',
            dest='privatebrowsing_enabled',
            default=True,
            action='store_false',
            help='Disable private browsing mode. [Default: enabled]'
    )
    parser.add_option(
            '--enable-plugins',
            dest='plugins_enabled',
            default=False,
            action='store_true',
            help='Set this to enable plugins. [Default: %default]'
    )
    parser.add_option(
            '--set-useragent',
            dest='useragent',
            metavar='AGENT',
            default=(
                'site2image - a webkit based websnapper. Version %s.'
                %(version)
            ),
            help='Set the Useragent String. [Default: %default]'
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
            dest='timeformat',
            default='%Y%m%d-%H%M%S.%s',
            metavar='FORMAT',
            help=(
                'Use this to set the time format applied to filename. ' +
                '[Default: %default]'
            )
    )
    parser.add_option(
            '--dir',
            dest='save_to_dir',
            metavar='DIR',
            default='/tmp',
            help=(
                'Set this to the dir where websites should be saved. ' +
                '[Default: %default]'
            )
    )
    parser.add_option(
            '--file-prefix',
            dest='fileprefix',
            metavar='PREFIX',
            default='site2image',
            help='Set this as a prefix of the filename. [Default: %default]'
    )
    parser.add_option(
            '--file-suffix',
            dest='filesuffix',
            default='random',
            metavar='SUFFIX',
            help=(
                'Setting the used filesuffix. If set to the special word ' +
                '`random\' (which is the default) it uses a created random ' +
                'number to prevent overrideing files. [Default: %default]'
            )
    )
    parser.add_option(
            '--disable-timestamp',
            dest='use_timestamp',
            default=True,
            action='store_false',
            help=(
                'Set this to disable timestamp in filename. ' +
                '[Default: use timestamp]'
            )
    )
    parser.add_option(
            '--disable-urlspart',
            dest='urlpart',
            default=True,
            action='store_false',
            help=(
                'Set this to disable the url in filename. ' +
                '[Default: use urlpart]'
            )
    )
    parser.add_option(
            '--http-proxy',
            dest='http_proxy',
            metavar='PROXY_ADDR:PROXY_PORT',
            default=None,
            type='string',
            help='Set this if you use a http(s) proxy. [Default: %default]',
            action='callback',
            callback=http_proxy_callback
    )
    parser.add_option(
            '--proxy-credentials',
            dest='proxy_credentials',
            metavar='PATH',
            action='callback',
            callback=proxy_credentials_callback,
            type='string',
            default=None,
            help=(
                'Set the path to the http(s) proxy credentials. ' +
                '[Default: %default]'
            )
    )
    parser.add_option(
            '--proxy-user',
            dest='proxy_user',
            default=None,
            help=SUPPRESS_HELP
    )
    parser.add_option(
            '--proxy-passwd',
            dest='proxy_passwd',
            default=None,
            help=SUPPRESS_HELP
    )
    parser.add_option(
            '--proxy-host',
            dest='proxy_host',
            default=None,
            help=SUPPRESS_HELP
    )
    parser.add_option(
            '--proxy-port',
            dest='proxy_port',
            default=None,
            help=SUPPRESS_HELP
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
            default='300x300',
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
            dest='snapshot_delay',
            default=0,
            type='int',
            metavar='SECONDS',
            help='Add n seconds for a delayed snapshot. [Default %default]'
    )
    parser.add_option(
            '--thumbnails-only',
            dest='thumbnails_only',
            action='store_true',
            default=False,
            help='Set this to get only thumbnails. [Default: %default]'
    )
    log_group = OptionGroup(
            parser,
            ('These options handles logging options')
    )
    log_group.add_option(
            '--loglevel',
            dest='loglevel',
            default=0,
            metavar='LEVEL',
            type='string',
            help=(
                'Set this to see some messages. Possible Values are: ' +
                'NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL ' +
                '[Default: NOTSET]'
            ),
            callback=loglevel_callback,
            action='callback'

    )
    log_group.add_option(
            '--no-logfile',
            dest='disable_logfile',
            action='store_true',
            default=False,
            help='Set this option if you want no logfile. [Default: %default]'
    )
    log_group.add_option(
            '--logfile',
            dest='logfile',
            default='/tmp/%s.log' %(prog),
            metavar='PATH',
            help='Set a path to the logfile. [Default: %default]'
    )
    log_group.add_option(
            '--no-stdout-logging',
            dest='disable_stdout_logging',
            default=False,
            action='store_true',
            help='Set this to disable logging on stdout. [Default: %default]'
    )
    parser.add_option(
            '--display',
            dest='display',
            metavar='DISPLAY',
            default=None,
            help=(
                'Force the DISPLAY to use. ' +
                'If none given (the default) it tries to get ' +
                'the DISPLAY from enviroment. If DISPLAY is not set in ' +
                'enviroment (in case you use xvfb) it tries to use ' +
                'DISPLAY=:99 wich is the default xvfb display.'
            )
    )
    parser.add_option_group(log_group)
    if dryrun:
        options, args = parser.parse_args([])
    else:
        options, args = parser.parse_args()
    if not options.display:
        try:
            options.display = os.environ['DISPLAY']
        except KeyError:
            options.display = ':99'
            os.environ['DISPLAY'] = options.display
    else:
        os.environ['DISPLAY'] = options.display

    if options.thumbnail_size:
        width, height = options.thumbnail_size.split('x')
        options.thumbnail_width = int(width)
        options.thumbnail_height = int(height)
    return options, args

if __name__ == '__main__':
    options, urls = cmdline_parser(version=__version__)
    if not options.disable_stdout_logging:
        stdout = True
    else:
        stdout = False
    if not options.disable_logfile:
        logfile = options.logfile
    else:
        logfile = None
    logger = get_logger()
    set_logging(
            logger,
            options.loglevel,
            stdout=stdout,
            logfile=logfile,
            logformat=logformat
    )
    app = SnapshotApp(Snapper, options, logger)
    app.start(*urls)
    sys.exit(app.app.exec_())
