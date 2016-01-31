# -*- coding: utf-8 -*-

import os

from setuptools import setup
from setuptools import find_packages


def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()


setup(
    name='snabb-neutron',
    version='0.1.dev0',
    description='Snabb plugins for Neutron',
    long_description=read('README.md') + read('HISTORY.rst') + read('LICENSE'),
    classifiers=[
        "Programming Language :: Python",
    ],
    author='Nikolay Nikolaev, Luke Gorrie',
    author_email='',
    url='',
    license='BSD',
    packages=find_packages(),
    install_requires=[
        'neutron',
    ],
    extras_require={
        'development': [
            'zest.releaser',
            'check-manifest',
        ],
    },
    entry_points="""
    [neutron.ml2.type_drivers]
    zone = snabb_neutron.type_zone:ZoneTypeDriver

    [neutron.ml2.mechanism_drivers]
    snabb = snabb_neutron.mechanism_snabb:SnabbMechanismDriver

    [neutron.db.alembic_migrations]
    snabb = snabb_neutron.db.migration:alembic_migrations
    """,
    include_package_data=True,
    zip_safe=False,
)
