#!/usr/bin/env python

from distutils.core import setup

setup(
        name='site2image',
        version='0.5.3',
        author='Robin Wittler',
        author_email='real@the-real.org',
        maintainer='Robin Wittler',
        maintainer_email='real@the-real.org',
        description='A Webkit based websnapper',
        url='git://the-real.org/site2image.git',
        download_url='git://the-real.org/site2image.git',
        license='gpl3',
        requires=['PyQt4',],
        packages=['websnapper',]
)



