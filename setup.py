from setuptools import setup, find_packages
import os
import sys


version = '0.2.0'

requires = []

idp_extras = [
]

am_extras = [
    'eduid-userdb>=0.0.4',
]

actions_extras = [
    'eduid-webapp>=0.2.1b11',
]

test_requires = [
    'WebTest==2.0.15',
    'mock==1.0.1',
]


testing_extras = test_requires + [
    'nose==1.3.3',
    'coverage==3.7.1',
    'nosexcover==1.0.10',
]

long_description = (
    open('README.txt').read()
    + '\n' +
    'Contributors\n'
    '============\n'
    + '\n' +
    open('CONTRIBUTORS.txt').read()
    + '\n' +
    open('CHANGES.txt').read()
    + '\n')

setup(name='eduid-action',
      version=version,
      description="Plugins for eduid-webapp actions",
      long_description=long_description,
      # Get more strings from
      # http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        ],
      keywords='',
      author='Enrique Perez Arnaud',
      author_email='enrique@cazalla.net',
      url='https://github.com/SUNET/',
      license='gpl',
      packages=['eduid_action.tou'],
      package_dir = {'': 'src'},
      namespace_packages=['eduid_action'],
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      extras_require={
          'idp': idp_extras,
          'am': am_extras,
          'actions': actions_extras,
          'testing': testing_extras,
          },
      entry_points={
          },
      )
