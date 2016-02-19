#keycloak-client-install(1) -- Configure Mellon SP to use Keycloak IdP

## SYNOPSIS

    keycloak-client-install [-h] [--no-root-check] [-v] [-d]
                            [--show-traceback] [--log-file LOG_FILE]
                            --app-name APP_NAME [--force]
                            [--template-dir TEMPLATE_DIR]
                            [--httpd-dir HTTPD_DIR] -r KEYCLOAK_REALM -s
                            KEYCLOAK_SERVER_URL
                            [-u KEYCLOAK_ADMIN_USERNAME] -p
                            KEYCLOAK_ADMIN_PASSWORD
                            [--mellon-key-file MELLON_KEY_FILE]
                            [--mellon-cert-file MELLON_CERT_FILE]
                            [--mellon-hostname MELLON_HOSTNAME]
                            [--mellon-endpoint-path MELLON_ENDPOINT_PATH]
                            [--mellon-entity-id MELLON_ENTITY_ID]
                            [--mellon-organization-name MELLON_ORGANIZATION_NAME]
                            [--mellon-organization-display-name MELLON_ORGANIZATION_DISPLAY_NAME]
                            [--mellon-organization-url MELLON_ORGANIZATION_URL]
                            [-l MELLON_PROTECTED_LOCATIONS]

    optional arguments:
      -h, --help            show this help message and exit
      --no-root-check       permit running by non-root (default: True)
      -v, --verbose         be chatty (default: False)
      -d, --debug           turn on debug info (default: False)
      --show-traceback      exceptions print traceback in addition to error
                            message (default: False)
      --log-file LOG_FILE   log file pathname (default: /var/log/keycloak-client-
                            install.log)
      --app-name APP_NAME   name of the web app being protected by mellon
                            (default: None)
      --force               forcefully override safety checks (default: False)

    Program Configuration:
      --template-dir TEMPLATE_DIR
                            Template location (default: /usr/share/python-
                            keycloak/templates)
      --httpd-dir HTTPD_DIR
                            Template location (default: /etc/httpd)

    Keycloak IdP:
      -r KEYCLOAK_REALM, --keycloak-realm KEYCLOAK_REALM
                            realm name (default: None)
      -s KEYCLOAK_SERVER_URL, --keycloak-server-url KEYCLOAK_SERVER_URL
                            Keycloak server URL (default: None)
      -u KEYCLOAK_ADMIN_USERNAME, --keycloak-admin-username KEYCLOAK_ADMIN_USERNAME
                            admin user name (default: admin) (default: admin)
      -p KEYCLOAK_ADMIN_PASSWORD, --keycloak-admin-password KEYCLOAK_ADMIN_PASSWORD
                            admin password (default: None)

    Mellon SP:
      --mellon-key-file MELLON_KEY_FILE
                            certficate key file (default: None)
      --mellon-cert-file MELLON_CERT_FILE
                            certficate file (default: None)
      --mellon-hostname MELLON_HOSTNAME
                            Machine's fully qualified host name (default:
                            jdennis_test.example.com)
      --mellon-endpoint-path MELLON_ENDPOINT_PATH
                            The root directory of the SAML2 endpoints, relative to
                            the root of the web server. mod_auth_mellon will
                            handle SAML requests to https://{mellon_hostname
                            }/{mellon-endpoint-path}/*. The path you specify must
                            be contained within the current Location directive.
                            (default: /mellon/)
      --mellon-entity-id MELLON_ENTITY_ID
                            SP SAML Entity ID (default: None)
      --mellon-organization-name MELLON_ORGANIZATION_NAME
                            Add SAML OrganizationName to SP metadata (default:
                            None)
      --mellon-organization-display-name MELLON_ORGANIZATION_DISPLAY_NAME
                            Add SAML OrganizationDisplayName to SP metadata
                            (default: None)
      --mellon-organization-url MELLON_ORGANIZATION_URL
                            Add SAML OrganizationURL to SP metadata (default:
                            None)
      -l MELLON_PROTECTED_LOCATIONS, --mellon-protected-locations MELLON_PROTECTED_LOCATIONS
                            Web location to protect with Mellon. May be specified
                            multiple times (default: [])


## DESCRIPTION

**keycloak-client-install** will configure a node running Apache with
mod_auth_mellon as SAML Service Provider (**SP**) utilizing a **Keycloak**
server as an Identity Provider (**IdP**).

## OPERATION

**keycloak-client-install** performs the following operational steps:

1.  Connect to Keycloak Server.

    A session is established with the Keycloak server. OAuth2 is used
    to log in as the admin user using the
    **--keycloak-admin-username** and **--keycloak-admin-password**
    options. The Keycloak server is identified by the
    **-keycloak-server-url** option. This step is performed first
    to assure the remaining steps can complete successfully. A session
    is maintained for efficiency reasons.
    
2.  Create directories.

    Files written by **keycloak-client-install** need a destination
    directory (see [FILES]). If the necessary directories are not
    present they are created.

3.  Set up template environment

    Many of the files written by **keycloak-client-install** are based
    on `jinga2` templates. The default template file location can be
    overridden with the **--template-dir** option.

4.  Set up Service Provider X509 Certificiates.

    A SAML SP must have a X509 certificate and key used to sign and
    optionally encrypt it's SAML messages sent to the SAML
    IdP. **keycloak-client-install** can generate a self-signed
    certificate for you or you may supply your own key and certificate
    via the **--mellon-key-file** and **--mellon-cert-file**
    options. The files must be in PEM format.

5.  Build Mellon httpd config file.

    The Mellon HTTPD configuration file tells `mod_auth_mellon` where
    to find things such as certificates and metadata files as well as
    what web resources to protect. It is generated from the
    `mellon_httpd.conf` template file. (see [FILES]). There is one
    mellon httpd conf file per application.

6.  Build Mellon SP metadata file.

    The Mellon SP needs to be registered with the Keycloak IdP. This
    forms a trust relationship and provides infomation to the IdP
    about the Mellon SP. Registering an SP with an IdP is done via a
    SP metadata file. The Mellon SP metadata also instructs
    `mod_auth_mellon` how to operate. The Mellon SP is generated from
    the `sp_metadata.tpl` template file.
    
7.  Query realms from Keycloak server, optionally create new realm.

    Keycloak supports multi-tenancy, it may serve many IdP's each one
    specified by a Keycloak realm. The **--keycloak-realm** option
    identifies which Keycloak realm we will bind to. The Keycloak
    realm may already exist on the Keycloak server, if it does
    **keycloak-client-install** will use it. If the Keycloak realm
    does not exist yet it will be created for you.

8.  Query realm clients from Keycloak server, optionally delete existing.

    SAML SP's are one type of Keycloak client that can be serviced by
    the Keycloak realm IdP. The Mellon SP is a new Keycloak client
    which needs to be added to the Keycloak realm. However we must
    assure the new client does not conflict with an existing client on
    the Keycloak realm. If the Mellon SP is already registered on the
    Keycloak realm **keycloak-client-install** will stop processing
    and exit with an error unless the **--force** option is
    used. **--force** will cause the existing client on the Keycloak
    realm to be deleted first so that it can be replaced in the next
    step. 

9.  Create new SP client in Keycloak realm.

    The Mellon SP is registered with the Keycloak realm on the
    Keycloak server by sending the Keycloak server the Mellon SP
    metadata to the Keycloak server.
    
11. Retrieve IdP metadata from Keycloak server.

    The Mellon SP needs SAML metadata that describes the Keycloak
    IdP. The metadata for the Keycloak IdP is fetched from the
    Keycloak server and stored in a location referenced in the Mellon
    SP httpd configuration file. (see [FILES]).

## STRUCTURE

The overarching organization is the web application. An independent
set of Mellon files are created per application and registered with
the Keycloak server. This permits multiple indpendent SAML Service
Providers and/or protected web resources to be handled by one Apache
instance. When you run **keycloak-client-install** you must supply an
application name via the **--app-name** option.

Within the web application you may protect via SAML multiple
independent web resources specified via the
**--mellon-protected-locations** /xxx option. This will cause a:

    <Location /xxx>
        MellonEnable auth
    </Location>

directive to be added to the Mellon HTTPD configuration file. The
Mellon SP parameters are located at the root of the web application
root, each protected location inherits from that.

## FILES

Files created by running **keycloak-client-install**:

  * *{httpd-dir}/conf.d/{app-name}\_mellon_keycloak\_{realm}.conf*

    This is the primary Mellon configuration file for the application.
    It binds to the Keycloak realm IdP. It is generated from the
    `mellon_httpd.conf` template file.
    
  * *{httpd-dir}/saml2/{app-name}.cert*

    The Mellon SP X509 certficate file in PEM format.

  * *{httpd-dir}/saml2/{app-name}.key*

    The Mellon SP X509 key file in PEM format.

  * *{httpd-dir}/saml2/{app-name}\_keycloak\_{realm}\_idp_metadata.xml*

    The Keycloak SAML2 IdP metadata file. It is fetched from the Keycloak
    server.

  * *{httpd-dir}/saml2/{app-name}\_sp_metadata.xml*

    The Mellon SAML2 SP metadata file. It is generated from the
    `sp_metadata.xml` template file.

Files referenced by **keycloak-client-install** when it runs:

  * */usr/share/python-keycloak/templates/\**

## DEBUGGING

The **--verbose** and **--debug** options can be used to increase the
level of detail emitted on the console. However, note the log file
logs everything at the `DEBUG` level so it is usually easier to
consult the log file when debugging (see [LOGGING])

## LOGGING

**keycloak-client-install** logs all it's operations to a rotated log
  file. The default log file can be overridden with the **--log-file**
  option. Each run of **keycloak-client-install** will create a new
  log file. Any previous log file will be rotated as a numbered verson
  keeping a maximum of 3 previous log files. Logging to the log file
  occurs at the `DEBUG` level that includes all HTTP requests and
  responses, this is useful for debugging.

## TEMPLATES

Many of the files generated by **keycloak-client-install** are
produced via jinja2 templates substituting values determined by
**keycloak-client-install** when it runs. The default template file
location can be overridden with the **--template-dir** option.

## AUTHOR

John Dennis <jdennis@redhat.com>
