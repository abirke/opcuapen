#!/usr/bin/env python3

from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md')) as readme_file:
    long_description = readme_file.read()

setup(
    name='opcuapen',

    description='',
    long_description=long_description,
    long_description_content_type='text/markdown',

    url='https://github.com/abirke/opcuapen',
    author='André Birke',
    author_email='abirke@campus.uni-paderborn.de',
    license='GNU GPLv3',

    python_requires='>=3',

    # Automatically generate version number from git tags
    use_scm_version=True,

    packages=find_packages(exclude=('tests',)),

    # Runtime dependencies
    install_requires=[
        'click',
        'cryptography',
        'docker',
        'gmpy2',
        'opcua==0.98.5',
    ],

    # Setup/build dependencies; setuptools_scm required for git-based versioning
    setup_requires=['setuptools_scm', 'pytest-runner'],

    # Test dependencies
    tests_require=['pytest'],

    # For a list of valid classifiers, see
    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],

    entry_points = {
        'console_scripts': [
            'opcuapen = opcuapen.clickif:cli'
        ]
    }
)
