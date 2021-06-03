# -*- coding: utf-8 -*-
"""
    Authors:
        Ioan-Dan Puslenghea <danioan.puslenghea@nxp.com>

    NXP (c) All rights reserved, 2021
"""
import os
import re

from setuptools import setup, find_packages

###################################################################

NAME = 'Utils-Product-Engineering'
PACKAGES = find_packages(where='src')
META_PATH = os.path.join('src', 'nxp', 'sw', 'amp', 'pe', 'utils', '__init__.py')

###################################################################

CURR_DIR = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with open(os.path.join(CURR_DIR, *parts), "r") as f:
        return f.read()


META_FILE = read(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta),
        META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


if __name__ == '__main__':
    setup(
        name=NAME,
        description=find_meta('description'),
        license=find_meta('license'),
        version=find_meta('version'),
        author=find_meta('author'),
        author_email=find_meta('email'),
        maintainer=find_meta('author'),
        maintainer_email=find_meta('email'),
        long_description=read(os.path.join('docs', 'README.md')),
        long_description_content_type="text/markdown",
        packages=PACKAGES,
        package_dir={'': 'src'},
        zip_safe=False,
        python_requires='>=2.7'
    )
