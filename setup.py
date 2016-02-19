#!/usr/bin/python

from distutils.core import setup

setup(name='keycloak',
      version='0.0',
      description='Python tools to setup and manage Keycloak',
      author='John Dennis',
      author_email='jdennis@redhat.com',
      packages = ['keycloak'],
      scripts = ['bin/keycloak-client-install'],
      data_files = [('/usr/share/python-keycloak/templates',
                     ['templates/mellon_httpd.conf',
                      'templates/sp_metadata.tpl'])],
      requires = ['requests', 'requests-oauthlib', 'jinja2'],
     )
