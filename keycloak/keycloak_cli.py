#!/usr/bin/python

from __future__ import print_function

import argparse
import json
from oauthlib.oauth2 import LegacyApplicationClient
import logging
import logging.handlers
from requests_oauthlib import OAuth2Session
import os
import requests
import six
import sys
import traceback

from six.moves.urllib.parse import quote as urlquote
from six.moves.urllib.parse import urlparse


# ------------------------------------------------------------------------------

logger = None
prog_name = os.path.basename(sys.argv[0])
LOG_FILE_ROTATION_COUNT = 3

TOKEN_URL_TEMPLATE = (
    '{server}/auth/realms/{realm}/protocol/openid-connect/token')
GET_REALMS_URL_TEMPLATE = (
    '{server}/auth/admin/realms')
CREATE_REALM_URL_TEMPLATE = (
    '{server}/auth/admin/realms')
DELETE_REALM_URL_TEMPLATE = (
    '{server}/auth/admin/realms/{realm}')
GET_REALM_METADATA_TEMPLATE = (
    '{server}/auth/realms/{realm}/protocol/saml/descriptor')

GET_CLIENTS_URL_TEMPLATE = (
    '{server}/auth/admin/realms/{realm}/clients')
CLIENT_DESCRIPTOR_URL_TEMPLATE = (
    '{server}/auth/admin/realms/{realm}/client-description-converter')
CREATE_CLIENT_URL_TEMPLATE = (
    '{server}/auth/admin/realms/{realm}/clients')
DELETE_CLIENT_URL_TEMPLATE = (
    '{server}/auth/admin/realms/{realm}/clients/{id}')

GET_INITIAL_ACCESS_TOKEN_TEMPLATE = (
    '{server}/auth/admin/realms/{realm}/clients-initial-access')
SAML2_CLIENT_REGISTRATION_TEMPLATE = (
    '{server}/auth/realms/{realm}/clients/saml2-entity-descriptor')

HTTP_FAILED_MSG_TEMPLATE = '{cmd} failed: {status}, {text}'


ADMIN_CLIENT_ID = 'admin-cli'

# ------------------------------------------------------------------------------


def configure_logging(options):
    global logger  # pylint: disable=W0603

    log_dir = os.path.dirname(options.log_file)
    if os.path.exists(log_dir):
        if not os.path.isdir(log_dir):
            raise ValueError('logging directory "{log_dir}" exists but is not '
                             'directory'.format(log_dir=log_dir))
    else:
        os.makedirs(log_dir)

    log_level = logging.ERROR
    if options.verbose:
        log_level = logging.INFO
    if options.debug:
        log_level = logging.DEBUG

        # These two lines enable debugging at httplib level
        # (requests->urllib3->http.client) You will see the REQUEST,
        # including HEADERS and DATA, and RESPONSE with HEADERS but
        # without DATA.  The only thing missing will be the
        # response.body which is not logged.
        try:
            import http.client as http_client  # Python 3
        except ImportError:
            import httplib as http_client      # Python 2

        http_client.HTTPConnection.debuglevel = 1

        # Turn on cookielib debugging
        if False:
            try:
                import http.cookiejar as cookiejar
            except ImportError:
                import cookielib as cookiejar  # Python 2
            cookiejar.debug = True

    logger = logging.getLogger(prog_name)

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            options.log_file, backupCount=LOG_FILE_ROTATION_COUNT)
    except IOError as e:
        print('Unable to open log file %s (%s)' % (options.log_file, e),
              file=sys.stderr)

    else:
        formatter = logging.Formatter(
            '%(asctime)s %(name)s %(levelname)s: %(message)s')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)

    # Set the log level on the logger to the lowest level
    # possible. This allows the message to be emitted from the logger
    # to it's handlers where the level will be filtered on a per
    # handler basis.
    logger.setLevel(1)

# ------------------------------------------------------------------------------


def json_pretty(text):
    return json.dumps(json.loads(text),
                      indent=4, sort_keys=True)


def server_name_from_url(url):
    return urlparse(url).netloc


def get_realm_names_from_realms(realms):
    return [x['realm'] for x in realms]


def get_client_client_ids_from_clients(clients):
    return [x['clientId'] for x in clients]


def find_client_by_name(clients, client_id):
    for client in clients:
        if client.get('clientId') == client_id:
            return client
    raise KeyError('{item} not found'.format(item=client_id))


# ------------------------------------------------------------------------------

class KeycloakREST(object):

    def __init__(self, server, session=None):
        self.server = server
        self.session = session

    def get_initial_access_token(self, realm_name):
        cmd_name = "get initial access token for realm '{realm}'".format(
            realm=realm_name)
        url = GET_INITIAL_ACCESS_TOKEN_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)

        params = {"expiration": 60,  # seconds
                  "count": 1}

        response = self.session.post(url, json=params)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        try:
            response_json = response.json()
        except ValueError as e:
            response_json = None

        if (not response_json or
            response.status_code != requests.codes.ok):
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, json_pretty(response.text))

        return response_json    # ClientInitialAccessPresentation

    def get_realms(self):
        cmd_name = "get realms"
        url = GET_REALMS_URL_TEMPLATE.format(server=self.server)

        logger.debug("%s on server %s", cmd_name, self.server)
        response = self.session.get(url)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        try:
            response_json = response.json()
        except ValueError as e:
            response_json = None

        if (not response_json or
            response.status_code != requests.codes.ok):
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, json_pretty(response.text))

        return response_json

    def create_realm(self, realm_name):
        cmd_name = "create realm '{realm}'".format(realm=realm_name)
        url = CREATE_REALM_URL_TEMPLATE.format(server=self.server)

        logger.debug("%s on server %s", cmd_name, self.server)

        params = {"enabled": True,
                  "id": realm_name,
                  "realm": realm_name,
                  }

        response = self.session.post(url, json=params)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        if response.status_code != requests.codes.created:
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, response.text)

    def delete_realm(self, realm_name):
        cmd_name = "delete realm '{realm}'".format(realm=realm_name)
        url = DELETE_REALM_URL_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)
        response = self.session.delete(url)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        if response.status_code != requests.codes.no_content:
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, response.text)

    def get_realm_metadata(self, realm_name):
        cmd_name = "get metadata for realm '{realm}'".format(realm=realm_name)
        url = GET_REALM_METADATA_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)
        response = self.session.get(url)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        if response.status_code != requests.codes.ok:
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, response.text)
        return response.text

    def get_clients(self, realm_name):
        cmd_name = "get clients in realm '{realm}'".format(realm=realm_name)
        url = GET_CLIENTS_URL_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)
        response = self.session.get(url)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        try:
            response_json = response.json()
        except ValueError as e:
            response_json = None

        if (not response_json or
            response.status_code != requests.codes.ok):
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, json_pretty(response.text))

        return response_json

    def get_client_descriptor(self, realm_name, metadata):
        cmd_name = "get client descriptor realm '{realm}'".format(
            realm=realm_name)
        url = CLIENT_DESCRIPTOR_URL_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)

        headers = {'Content-Type': 'application/xml;charset=utf-8'}

        response = self.session.post(url, headers=headers, data=metadata)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        try:
            response_json = response.json()
        except ValueError as e:
            response_json = None

        if (not response_json or
            response.status_code != requests.codes.ok):
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, json_pretty(response.text))

        return response_json

    def create_client_from_descriptor(self, realm_name, descriptor):
        cmd_name = "create client from descriptor "
        "'{client_id}'in realm '{realm}'".format(
            client_id=descriptor['clientId'], realm=realm_name)
        url = CREATE_CLIENT_URL_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)

        response = self.session.post(url, json=descriptor)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        if response.status_code != requests.codes.created:
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, response.text)

    def create_client(self, realm_name, metadata):
        logger.debug("create client in realm %s on server %s",
                     realm_name, self.server)
        descriptor = self.get_client_descriptor(realm_name, metadata)
        self.create_client_from_descriptor(realm_name, descriptor)
        return descriptor

    def register_client(self, initial_access_token, realm_name, metadata):
        cmd_name = "register_client realm '{realm}'".format(
            realm=realm_name)
        url = SAML2_CLIENT_REGISTRATION_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name))

        logger.debug("%s on server %s", cmd_name, self.server)

        headers = {'Content-Type': 'application/xml;charset=utf-8'}

        if initial_access_token:
            headers['Authorization'] = 'Bearer {token}'.format(
                token=initial_access_token)

        response = self.session.post(url, headers=headers, data=metadata)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        try:
            response_json = response.json()
        except ValueError as e:
            response_json = None

        if (not response_json or
            response.status_code != requests.codes.created):
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, json_pretty(response.text))

        return response_json    # ClientRepresentation

    def delete_client(self, realm_name, id):
        cmd_name = "delete client id '{id}'in realm '{realm}'".format(
            id=id, realm=realm_name)
        url = DELETE_CLIENT_URL_TEMPLATE.format(
            server=self.server, realm=urlquote(realm_name),
            id=urlquote(id))

        logger.debug("%s on server %s", cmd_name, self.server)
        response = self.session.delete(url)
        logger.debug("%s response code: %s %s",
                     cmd_name, response.status_code, response.reason)

        if response.status_code != requests.codes.no_content:
            logger.error("%s error: status=%s (%s) text=%s",
                         cmd_name, response.status_code, response.reason,
                         response.text)
            raise ValueError(HTTP_FAILED_MSG_TEMPLATE.format(
                cmd=cmd_name, status=response.reason, text=response.text))

        logger.debug("%s response = %s", cmd_name, response.text)

# ------------------------------------------------------------------------------


class KeycloakAdminConnection(KeycloakREST):

    def __init__(self, server, realm, client_id, username, password):
        self.server = server
        self.realm = realm
        self.client_id = client_id
        self.username = username
        self.password = password

        session = self._create_session()

        super(KeycloakAdminConnection, self).__init__(server, session)

    def _create_session(self):
        token_url = TOKEN_URL_TEMPLATE.format(
            server=self.server, realm=urlquote(self.realm))
        refresh_url = token_url

        client = LegacyApplicationClient(client_id=self.client_id)
        session = OAuth2Session(client=client,
                                auto_refresh_url=refresh_url,
                                auto_refresh_kwargs={
                                    'client_id': self.client_id})

        token = session.fetch_token(token_url=token_url,
                                    username=self.username,
                                    password=self.password,
                                    client_id=self.client_id)

        return session


class KeycloakNoAuthConnection(KeycloakREST):

    def __init__(self, server):
        self.server = server

        session = self._create_session()

        super(KeycloakNoAuthConnection, self).__init__(server, session)

    def _create_session(self):
        session = requests.Session()

        return session

# ------------------------------------------------------------------------------


def do_list_realms(options, conn):
    realms = conn.get_realms()
    realm_names = get_realm_names_from_realms(realms)
    print('\n'.join(sorted(realm_names)))


def do_create_realm(options, conn):
    conn.create_realm(options.realm_name)


def do_delete_realm(options, conn):
    conn.delete_realm(options.realm_name)


def do_get_realm_metadata(options, conn):
    metadata = conn.get_realm_metadata(options.realm_name)
    print(metadata)


def do_list_clients(options, conn):
    clients = conn.get_clients(options.realm_name)
    client_ids = get_client_client_ids_from_clients(clients)
    print('\n'.join(sorted(client_ids)))


def do_create_client(options, conn):
    metadata = options.metadata.read()
    descriptor = conn.create_client(options.realm_name, metadata)


def do_register_client(options, conn):
    metadata = options.metadata.read()
    client_representation = conn.register_client(
        options.initial_access_token, options.realm_name, metadata)


def do_delete_client(options, conn):
    clients = conn.get_clients(options.realm_name)
    client = find_client_by_name(clients, options.client_name)
    id = client.get('id')
    conn.delete_client(options.realm_name, id)


# ------------------------------------------------------------------------------

verbose_help = '''

The structure of the command line arguments is "noun verb" where noun
is one of Keycloak's data items (e.g. realm, client, etc.) and the
verb is an action to perform on the item. Each of the nouns and verbs
may have their own set of arguments which must follow the noun or
verb.

For example to delete the client XYZ in the realm ABC:

{prog_name} -s http://example.com:8080 -p password client delete -r ABC -c XYZ

where 'client' is the noun, 'delete' is the verb and -r ABC -c XYZ are
arguments to the delete action.

If the comman completes successfully the exit status is 0. The exit
status is 1 if an authenticated connection with the server cannont be
successfully established. The exit status is 2 if the REST operation
fails.

The server should be a scheme://hostname:port URL.
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
                        default='/tmp/{prog_name}.log'.format(
                            prog_name=prog_name),
                        help='log file pathname')

    parser.add_argument('--permit-insecure-transport',  action='store_true',
                        help='Normally secure transport such as TLS '
                        'is required, defeat this check')

    group = parser.add_argument_group('Server')

    group.add_argument('-s', '--server',
                       required=True,
                       help='DNS name or IP address of Keycloak server')

    group.add_argument('-u', '--admin-username',
                       default='admin',
                       help='admin user name (default: admin)')

    group.add_argument('-p', '--admin-password',
                       required=True,
                       help='admin password')

    cmd_parsers = parser.add_subparsers(help='avaiable commands')

    # --- realm commands ---
    realm_parser = cmd_parsers.add_parser('realm',
                                          help='realm operations')

    sub_parser = realm_parser.add_subparsers(help='realm commands')

    cmd_parser = sub_parser.add_parser('list',
                                       help='list realm names')
    cmd_parser.set_defaults(func=do_list_realms)

    cmd_parser = sub_parser.add_parser('create',
                                       help='create new realm')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')
    cmd_parser.set_defaults(func=do_create_realm)

    cmd_parser = sub_parser.add_parser('delete',
                                       help='delete existing realm')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')
    cmd_parser.set_defaults(func=do_delete_realm)

    cmd_parser = sub_parser.add_parser('metadata',
                                       help='retrieve realm metadata')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')
    cmd_parser.set_defaults(func=do_get_realm_metadata)

    # --- client commands ---
    client_parser = cmd_parsers.add_parser('client',
                                           help='client operations')

    sub_parser = client_parser.add_subparsers(help='client commands')

    cmd_parser = sub_parser.add_parser('list',
                                       help='list client names')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')

    cmd_parser.set_defaults(func=do_list_clients)

    cmd_parser = sub_parser.add_parser('create',
                                       help='create new client')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')
    cmd_parser.add_argument('-m', '--metadata', type=argparse.FileType('rb'),
                            required=True,
                            help='SP metadata file or stdin')
    cmd_parser.set_defaults(func=do_create_client)

    cmd_parser = sub_parser.add_parser('register',
                                       help='register new client')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')
    cmd_parser.add_argument('-m', '--metadata', type=argparse.FileType('rb'),
                            required=True,
                            help='SP metadata file or stdin')
    cmd_parser.add_argument('--initial-access-token', required=True,
                            help='realm initial access token for '
                            'client registeration')
    cmd_parser.set_defaults(func=do_register_client)

    cmd_parser = sub_parser.add_parser('delete',
                                       help='delete existing client')
    cmd_parser.add_argument('-r', '--realm-name', required=True,
                            help='realm name')
    cmd_parser.add_argument('-c', '--client-name', required=True,
                            help='client name')
    cmd_parser.set_defaults(func=do_delete_client)

    # Process command line arguments
    options = parser.parse_args()
    configure_logging(options)

    if options.permit_insecure_transport:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    try:
        noauth_conn = KeycloakNoAuthConnection(options.server)

        admin_conn = KeycloakAdminConnection(options.server, 'master',
                                             ADMIN_CLIENT_ID,
                                             options.admin_username,
                                             options.admin_password)
    except Exception as e:
        if options.show_traceback:
            traceback.print_exc()
        print(six.text_type(e), file=sys.stderr)
        result = 1
        return result

    try:
        if options.func == do_register_client:
            conn = noauth_conn
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
