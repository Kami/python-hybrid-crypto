import os
import sys

from os.path import join as pjoin

from setuptools import setup


def read_version_string():
    version = None
    sys.path.insert(0, pjoin(os.getcwd()))
    from hybrid_crypto import __version__
    version = __version__
    sys.path.pop(0)
    return version

with open('requirements.txt', 'r') as fp:
    content = fp.read().strip()
    requirements = content.split('\n')


setup(
    name='hybrid-crypto',
    version=read_version_string(),
    long_description=open('README.rst').read() + '\n\n' +
    open('CHANGES.rst').read(),
    packages=[
        'hybrid_crypto'
    ],
    install_requires=requirements,
    url='https://github.com/Kami/python-hybrid-crypto/',
    license='Apache License (2.0)',
    author='Tomaz Muraus',
    author_email='tomaz+pypi@tomaz.me',
    description='Python module which exposes a simple hybrid '
                'cryptography abstraction on top of KeyCzar and pycrypto.',
    test_suite='tests',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
