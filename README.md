# keycloak-httpd-client-install

Keycloak is a federated Identity Provider (IdP) that supports a
variety of authentication protocols. Apache HTTPD supports a variety
of authentication modules which have the capability of connecting to
a Keycloak IdP instance to perform authentication.

Before an Apache HTTPD authentication module can utilize Keycloak a
number of configuration steps must be performed. Most of these steps
are done on the node running the Apache HTTPD instance. The once the
Apache HTTPD authentication module is fully configured it must be
registered with the Keycloak server as a client.

This project contains both a library and an executable tool
(keycloak-httpd-client-install) that is capable of performing the
above steps. See the documentation for the tool in
doc/keycloak-httpd-client-install.md. The tool automates and greatly
simplifies the task of setting up federated authentication for Apache
HTTPD in conjunction with Keycloak.

Currently the tool supports the following Apache HTTPD authentication
modules and authentication protocols:

| Authentication Module | Protocol |
|-----------------------|----------|
| mod_auth_mellon       | SAML2    |
