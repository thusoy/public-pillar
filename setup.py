#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import unicode_literals

from setuptools import setup
import sys


install_requires = [
    'pycrypto',
    'pyyaml',
]

if sys.version_info < (2, 7, 0):
    install_requires.append('argparse')

setup(
    name='ppillar',
    version='0.2.1',
    author='Tarjei Husøy',
    author_email='tarjei@roms.no',
    url='https://github.com/thusoy/public-pillar',
    description="A PKI encrypted datastructure to keep secrets in the public",
    py_modules=['ppillar'],
    install_requires=install_requires,
    extras_require={
        'test': ['coverage', 'mock', 'nose'],
    },
    entry_points={
        'console_scripts': [
            'ppillar = ppillar:cli',
        ]
    },
    classifiers=[
        # 'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
        'Development Status :: 3 - Alpha',
        # 'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
)
