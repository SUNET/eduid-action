from setuptools import setup

version = '0.2.1b7'

requires = [
    'python-u2flib-server',
    'fido2 >= 0.5.0',
    'eduid-userdb>=0.4.0b12',
    'eduid-common[webapp]>=0.3.5b9',
]

idp_extras = [
]

am_extras = [
]

actions_extras = [
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
      packages=[
          'eduid_action.common',
          'eduid_action.tou',
          'eduid_action.mfa',
      ],
      package_dir={'': 'src'},
      namespace_packages=['eduid_action'],
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      extras_require={
          'idp': idp_extras,
          'am': am_extras,
          'actions': actions_extras,
      },
      entry_points={
      },
      )
