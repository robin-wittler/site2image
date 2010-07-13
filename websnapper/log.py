#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
from logging import handlers

logformat = (
        '%(asctime)s %(name)s[%(process)d] ' +
        '%(levelname)s: %(message)s'
)

__author__ = 'Robin Wittler'
__contact__ = 'real@the-real.org'
__licence__ = 'GPL3'
__version__ = '0.3.1'


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

def get_logger():
    return logging.getLogger(os.path.splitext(sys.argv[0])[0])

def set_logging(logger, loglevel, stdout=False,
        logfile=None, logformat=logformat):

    logger.setLevel(loglevel)
    formatter = logging.Formatter(logformat)
    if stdout:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(loglevel)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    if logfile:
        file_handler = handlers.WatchedFileHandler(logfile)
        file_handler.setLevel(loglevel)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger

