#!/usr/bin/python3

from __future__ import print_function

import argparse
import logging
import logging.handlers
import os
import sys
import traceback

import six

from keycloak_httpd_client import keycloak_rest
import keycloak_httpd_client.utils as utils

# ------------------------------------------------------------------------------

prog_name = os.path.basename(sys.argv[0])
logger = None

# ------------------------------------------------------------------------------


def do_server_info(options, conn):
    server_info = conn.get_server_info()
    print(utils.py_json_pretty(server_info))


def do_list_realms(options, conn):
    realms = conn.get_realms()
    realm_names = utils.get_realm_names_from_realms(realms)
    print('\n'.join(sorted(realm_names)))


def do_create_realm(options, conn):
    conn.create_realm(options.realm_name)


def do_delete_realm(options, conn):
    conn.delete_realm(options.realm_name)


def do_get_realm_saml_metadata(options, conn):
    metadata = conn.get_realm_saml_metadata(options.realm_name)
    print(metadata)


def do_list_clients(options, conn):
    clients = conn.get_clients(options.realm_name)
    client_ids = utils.get_client_client_ids_from_clients(clients)
    print('\n'.join(sorted(client_ids)))


def do_show_client(options, conn):
    client_rep = conn.get_client_by_clientid(options.realm_name,
                                             options.clientid)
    print(utils.py_json_pretty(client_rep))

def do_get_client_secret(options, conn):
    obj_id = conn.get_client_id_by_clientid(options.realm_name,
                                            options.clientid)
    secret = conn.get_client_secret_by_id(options.realm_name, obj_id)
    print(utils.py_json_pretty(secret))

def do_regenerate_client_secret(options, conn):
    obj_id = conn.get_client_id_by_clientid(options.realm_name,
                                            options.clientid)
    secret = conn.regenerate_client_secret_by_id(options.realm_name, obj_id)
    print(utils.py_json_pretty(secret))

def do_create_client(options, conn):
    client_data = options.client_data.read()
    if options.client_data_format == 'saml':
        client_representation = \
            conn.convert_saml_metadata_to_client_representation(options.realm_name,
                                                                client_data)
    elif options.client_data_format == 'default':
        client_representation = client_data
    else:
        raise ValueError('Unknown client_data_format "%s"' %
                         options.client_data_format)
    descriptor = \
        conn.create_client_from_client_representation(options.realm_name,
                                                      client_representation)


def do_register_client(options, conn):
    client_data = options.client_data.read()
    client_representation = conn.register_client(
        options.initial_access_token, options.realm_name,
        options.client_data_format, client_data)

def do_delete_client(options, conn):
    conn.delete_client_by_clientid(options.realm_name, options.clientid)

def do_client_test(options, conn):
    'experimental test code used during development'

    uri = 'https://openstack.jdennis.oslab.test:5000/v3/mellon/fooResponse'

    conn.remove_client_by_name_redirect_uri(options.realm_name,
                                            options.clientid,
                                            uri)

# ------------------------------------------------------------------------------

verbose_help = '''

The structure of the command line arguments is "noun verb" where noun
is one of Keycloak's data items (e.g. realm, client, etc.) and the
verb is an action to perform on the item. Each of the nouns and verbs
may have their own set of arguments which must follow the noun or
verb.

For example to delete the client XYZ in the realm ABC:

echo password | {prog_name} -s http://example.com:8080 -P - client delete -r ABC -c XYZ

where 'client' is the noun, 'delete' is the verb and -r ABC -c XYZ are
arguments to the delete action.

If the command completes successfully the exit status is 0. The exit
status is 1 if an authenticated connection with the server cannont be
successfully established. The exit status is 2 if the REST operation
fails.

The server should be a scheme://hostname:port URL.

server info
server realms

realm create
realm delete
realm metadata
'''


def main():
    global logger
    result = 0

    parser = argparse.ArgumentParser(description='Keycloak REST client',
                                     prog=prog_name,
                                     epilog=verbose_help.format(prog_name=prog_name),
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='be chatty')

    parser.add_argument('-d', '--debug', action='store_true',
                        help='turn on debug info')

    parser.add_argument('--show-traceback', action='store_true',
                        help='exceptions print traceback in addition to '
                             'error message')

    parser.add_argument('--log-file',
                        default='{prog_name}.log'.format(
                            prog_name=prog_name),
                        help='log file pathname')

    parser.add_argument('--permit-insecure-transport', action='store_true',
                        help='Normally secure transport such as TLS '
                        'is required, defeat this check')

    parser.add_argument('--tls-verify', action=utils.TlsVerifyAction,
                        default=True,
                        help='TLS certificate verification for requests to'
                        ' the server. May be one of case insenstive '
                        '[true, yes, on] to enable,'
                        '[false, no, off] to disable.'
                        'Or the pathname to a OpenSSL CA bundle to use.'
                        ' Default is True.')

    group = parser.add_argument_group('Server')

    group.add_argument('-s', '--server',
                       required=True,
                       help='DNS name or IP address of Keycloak server')

    group.add_argument('-a', '--auth-role',
                       choices=keycloak_rest.AUTH_ROLES,
                       default='root-admin',
                       help='authenticating as what type of user (default: root-admin)')

    group.add_argument('-u', '--admin-username',
                       default='admin',
                       help='admin user name (default: admin)')

    group.add_argument('-P', '--admin-password-file',
                       type=argparse.FileType('rb'),
                       help=('file containing admin password '
                             '(or use a hyphen "-" to read the password '
                             'from stdin)'))

    group.add_argument('--admin-realm',
                       default='master',
                       help='realm admin belongs to')

    cmd_parsers = parser.add_subparsers(help='available commands')

    # --- server commands ---
    server_parsers = cmd_parsers.add_parser('server',
                                            help='server commands, use "server -h" '
                                            'to see available commands')
    server_sub_parser = server_parsers.add_subparsers(help='server commands')

    # --- info
    cmd_parser = server_sub_parser.add_parser('info',
                                              help='dump server info')
    cmd_parser.set_defaults(func=do_server_info)

    # --- realms
    cmd_parser = server_sub_parser.add_parser('realms',
                                              help='list realm names')
    cmd_parser.set_defaults(func=do_list_realms)

    # --- realm commands ---
    realm_parsers = cmd_parsers.add_parser('realm',
                                           help='realm commands, use "realm -h" '
                                           'to see available commands')
    realm_sub_parser = realm_parsers.add_subparsers(help='realm commands')

    realm_parsers.add_argument('-r', '--realm-name', required=True,
                               help='realm name')

    # --- realm create
    cmd_parser = realm_sub_parser.add_parser('create',
                                             help='create new realm')
    cmd_parser.set_defaults(func=do_create_realm)

    # --- realm delete
    cmd_parser = realm_sub_parser.add_parser('delete',
                                             help='delete existing realm')
    cmd_parser.set_defaults(func=do_delete_realm)

    # --- realm saml-metadata
    cmd_parser = realm_sub_parser.add_parser('saml-metadata',
                                             help='retrieve realm SAML metadata')
    cmd_parser.set_defaults(func=do_get_realm_saml_metadata)

    # --- client commands ---
    client_parsers = cmd_parsers.add_parser('client',
                                            help='client operations')
    client_sub_parser = client_parsers.add_subparsers(help='client commands')


    client_parsers.add_argument('-r', '--realm-name', required=True,
                                help='realm name')

    client_parsers.add_argument('-c', '--clientid', required=True,
                                help='clientid')

    # --- client list
    cmd_parser = client_sub_parser.add_parser('list',
                                              help='list clientids')
    cmd_parser.set_defaults(func=do_list_clients)

    # --- client show
    cmd_parser = client_sub_parser.add_parser('show',
                                              help='show client representation')
    cmd_parser.set_defaults(func=do_show_client)

    # --- client secret show
    cmd_parser = client_sub_parser.add_parser('secret',
                                              help='show client secret')
    cmd_parser.set_defaults(func=do_get_client_secret)

    # --- client secret regenerate
    cmd_parser = client_sub_parser.add_parser('regenerate-secret',
                                              help='regenerate client secret')
    cmd_parser.set_defaults(func=do_regenerate_client_secret)

    # --- client create
    cmd_parser = client_sub_parser.add_parser('create',
                                              help='create new client')
    cmd_parser.add_argument('--client-data',
                            type=argparse.FileType('rb'),
                            required=True,
                            help='client description (i.e. JSON, XML) '
                            'file or stdin')
    cmd_parser.add_argument('--client-data-format',
                            choices=['default', 'saml'],
                            default='default',
                            help='Client data type')
    cmd_parser.set_defaults(func=do_create_client)

    # --- client register
    cmd_parser = client_sub_parser.add_parser('register',
                                              help='register new client')
    cmd_parser.add_argument('--client-data',
                            type=argparse.FileType('rb'),
                            required=True,
                            help='client description (i.e. JSON, XML) '
                            'file or stdin')
    cmd_parser.add_argument('--client-data-format',
                            choices=['default', 'saml', 'oidc'],
                            default='default',
                            help='Client data type')
    cmd_parser.add_argument('--initial-access-token', required=True,
                            help='realm initial access token for '
                            'client registeration')
    cmd_parser.set_defaults(func=do_register_client)

    # --- client delete
    cmd_parser = client_sub_parser.add_parser('delete',
                                              help='delete existing client')
    cmd_parser.set_defaults(func=do_delete_client)


    # Process command line arguments
    options = parser.parse_args()
    utils.configure_logging(options)
    logger = logging.getLogger(prog_name)

    if options.permit_insecure_transport:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Get admin password
    options.admin_password = None

    # 1. Try password file
    if options.admin_password_file is not None:
        options.admin_password = options.admin_password_file.readline().strip()
        options.admin_password_file.close()

    # 2. Try KEYCLOAK_ADMIN_PASSWORD environment variable
    if options.admin_password is None:
        if (('KEYCLOAK_ADMIN_PASSWORD' in os.environ) and
                (os.environ['KEYCLOAK_ADMIN_PASSWORD'])):
            options.admin_password = os.environ['KEYCLOAK_ADMIN_PASSWORD']

    try:
        anonymous_conn = keycloak_rest.KeycloakAnonymousConnection(
            options.server,
            options.tls_verify)

        admin_conn = keycloak_rest.KeycloakAdminConnection(options.server,
                                                           options.auth_role,
                                                           options.admin_realm,
                                                           keycloak_rest.ADMIN_CLIENT_ID,
                                                           options.admin_username,
                                                           options.admin_password,
                                                           options.tls_verify)
    except Exception as e:
        if options.show_traceback:
            traceback.print_exc()
        print(six.text_type(e), file=sys.stderr)
        result = 1
        return result

    try:
        if options.func == do_register_client:
            conn = admin_conn
        else:
            conn = admin_conn
        result = options.func(options, conn)
    except Exception as e:
        if options.show_traceback:
            traceback.print_exc()
        print(six.text_type(e), file=sys.stderr)
        result = 2
        return result

    return result

# ------------------------------------------------------------------------------

if __name__ == '__main__':
    sys.exit(main())
else:
    logger = logging.getLogger('keycloak-cli')
