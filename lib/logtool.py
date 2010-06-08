#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'Robin Wittler <real@the-real.org>'
__version__ = '0.0.1'
__licence__ = 'GPL3'

import sys
import logging
import logging.handlers

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
