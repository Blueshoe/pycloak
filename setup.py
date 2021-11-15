#!/usr/bin/env python

import io
from os.path import exists
from setuptools import setup, find_packages

__version__ = "0.0.10"

setup(
    name='pycloak',
    version=__version__,
    author='Blueshoe',
    author_email='veit@blueshoe.de',
    description='Utils around Keycloak and other OIDC clients.',
    long_description=io.open('README.md', encoding='utf-8').read() if exists("README.md") else "",
    packages=[
        "pycloak",
    ],
    install_requires=[
        'Django>=2.2',
        'PyJWT~=2.1.0',
    ],
    python_requires='>=3.8',
    include_package_data=True,
    scripts=[],
    license='Copyright',
    classifiers=[
        # 'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        # 'License :: OSI Approved :: MIT License',
        'Framework :: Django',
        'Framework :: Django :: 2.2',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe=False,
)
