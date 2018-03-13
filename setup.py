#!/usr/bin/env python3
from distutils.core import setup

setup(
        name = 'makeelf',
        packages = ['makeelf'],
        version = '0.2.0',
        description = 'ELF reader-writer library',
        url = 'https://github.com/v3l0c1r4pt0r/makeelf',
        author = 'v3l0c1r4pt0r',
        author_email = 'v3l0c1r4pt0r@gmail.com',
        classifiers = [
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Development Status :: 2 - Pre-Alpha',
            'Intended Audience :: Developers',
            'Topic :: Software Development :: Libraries :: Python Modules',
            ],
        long_description = '''MakeELF is a Python library to parse, modify and create ELF binaries. It provides following features:

 - easy to use, standard Python interface
 - reading existing ELF files to Python representation
 - modification of every aspect of ELF format structures
 - ability to skip any validation to test other parsers for potential errors
 - creating new valid ELF files with just one step
 - easy serialization of every structure present in ELF file
''',
        )
