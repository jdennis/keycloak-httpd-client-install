#!/usr/bin/python

from distutils.core import setup

name = 'keycloak-httpd-client'

setup(name=name,
      version='0.0',
      description='Tools to configure Apache HTTPD as Keycloak client',
      author='John Dennis',
      author_email='jdennis@redhat.com',
      license='GPLv3',
      packages = ['keycloak'],
      scripts = ['bin/keycloak-httpd-client-install'],
      data_files = [('/usr/share/python-{name}/templates'.format(name=name),
                     ['templates/mellon_httpd.conf',
                      'templates/sp_metadata.tpl'])],
      requires = ['requests', 'requests_oauthlib', 'jinja2'],
      classifiers = [           # see https://pypi.python.org/pypi?%3Aaction=list_classifiers
          "Programming Language :: Python",
          "Programming Language :: Python :: 3",
          "Development Status :: 3 - Alpha",
          "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
          "Operating System :: POSIX",
      ],
     )
