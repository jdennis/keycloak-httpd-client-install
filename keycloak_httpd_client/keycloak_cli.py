from __future__ import print_function

import argparse
import inspect
import json
import logging
import logging.handlers
import os
import sys
import traceback

from oauthlib.oauth2 import LegacyApplicationClient
import requests
from requests_oauthlib import OAuth2Session
import six
from six.moves.urllib.parse import quote as urlquote
from six.moves.urllib.parse import urlparse


# ------------------------------------------------------------------------------

logger = None
prog_name = os.path.basename(sys.argv[0])
AUTH_ROLES = ['root-admin', 'realm-admin', 'anonymous']

LOG_FILE_ROTATION_COUNT = 3

URL_OIDC_TOKEN = (
    '{server}/auth/realms/{realm}/protocol/openid-connect/token')
URL_SERVER_INFO = (
    '{server}/auth/admin/serverinfo/')
URL_REALMS = (
    '{server}/auth/admin/realms')
URL_REALMS_REALM = (
    '{server}/auth/admin/realms/{realm}')
URL_REALM_SAML_DESCRIPTOR = (
    '{server}/auth/realms/{realm}/protocol/saml/descriptor')

URL_CLIENTS = (
    '{server}/auth/admin/realms/{realm}/clients')
URL_CLIENTS_ID = (
    '{server}/auth/admin/realms/{realm}/clients/{id}')
URL_CLIENT_SECRET = (
    '{server}/auth/admin/realms/{realm}/clients/{id}/client-secret')
URL_CLIENT_DESCRIPTION_CONVERTER = (
    '{server}/auth/admin/realms/{realm}/client-description-converter')

URL_INITIAL_ACCESS_TOKEN = (
    '{server}/auth/admin/realms/{realm}/clients-initial-access')
URL_CLIENT_REGISTRATION_CLIENT_REPRESENTATION = (
    '{server}/auth/realms/{realm}/clients-registrations/default')
URL_CLIENT_REGISTRATION_SAML2 = (
    '{server}/auth/realms/{realm}/clients-registrations/saml2-entity-descriptor')
URL_CLIENT_REGISTRATION_OIDC = (
    '{server}/auth/realms/{realm}/clients-registrations/openid-connect')

URL_CLIENT_PROTOCOL_MAPPER_MODEL = (
    '{server}/auth/admin/realms/{realm}/clients/{id}/protocol-mappers/models')


ADMIN_CLIENT_ID = 'admin-cli'

# ------------------------------------------------------------------------------


class RESTError(Exception):
    def __init__(self, cmd_name, response):
        super(RESTError, self).__init__()
        self.cmd_name = cmd_name
        self.status_code = response.status_code
        self.status_reason = response.reason
        self.response_json = response.json()
        self.response_text = response.text
        self.error_description = None
        self.error = None

        self.message = 'RESTError [{cmd_name}] '.format(cmd_name=cmd_name)

        self.message += '{status_reason}({status_code}): '.format(
            status_reason=self.status_reason,
            status_code=self.status_code)

        if self.response_json:
            self.error_description = self.response_json.get('error_description')
            if self.error_description is None:
                self.error_description = self.response_json.get('errorMessage')
            self.error = self.response_json.get('error', '')
            self.message += '"{error_description}" [{error}]'.format(
                error_description=self.error_description,
                error=self.error)
        else:
            self.message += '"{response_text}"'.format(
                response_text=self.response_text)

        logger.error(self.message)
        self.args = (self.message,)

    def __str__(self):
        return self.message

# ------------------------------------------------------------------------------


def configure_logging(options):
    global logger  # pylint: disable=W0603

    log_dir = os.path.dirname(options.log_file)
    if not log_dir:
        log_dir = '.'
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


def py_json_pretty(py_json):
    return json_pretty(json.dumps(py_json))


def server_name_from_url(url):
    return urlparse(url).netloc


def get_realm_names_from_realms(realms):
    return [x['realm'] for x in realms]


def get_client_client_ids_from_clients(clients):
    return [x['clientId'] for x in clients]


# ------------------------------------------------------------------------------

class KeycloakREST(object):

    def __init__(self, server, auth_role=None, session=None):
        self.server = server
        self.auth_role = auth_role
        self.session = session

    def _log_rest_response(self, cmd_name, response):
        fname = inspect.stack()[1][3]
        logger.debug('%s() [%s] response code: %s %s, '
                     'Content-Length=%s Content-Type=%s',
                     fname, cmd_name, response.status_code, response.reason,
                     response.headers.get('Content-Length'),
                     response.headers.get('Content-Type'))


    def _log_rest_request(self, cmd_name, url, data=None):
        fname = inspect.stack()[1][3]
        logger.debug('%s() [%s] url=%s%s',
                     fname, cmd_name, url,
                     ' data=%s' % data if data else '')

    def _log_return_value(self, return_value, is_json=True):
        fname = inspect.stack()[1][3]
        if is_json:
            value = py_json_pretty(return_value)
        else:
            value = return_value
        logger.debug('%s() returns %s', fname, value)

    def get_initial_access_token(self, realm_name):
        cmd_name = 'get initial access token for realm "{realm}"'.format(
            realm=realm_name)
        url = URL_INITIAL_ACCESS_TOKEN.format(
            server=self.server, realm=urlquote(realm_name))

        params = {'expiration': 60,  # seconds
                  'count': 1}

        self._log_rest_request(cmd_name, url, params)
        response = self.session.post(url, json=params)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json    # ClientInitialAccessPresentation

    def get_server_info(self):
        cmd_name = 'get server info'
        url = URL_SERVER_INFO.format(server=self.server)

        self._log_rest_request(cmd_name, url)
        response = self.session.get(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def get_realms(self):
        cmd_name = 'get realms'
        url = URL_REALMS.format(server=self.server)

        self._log_rest_request(cmd_name, url)
        response = self.session.get(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def create_realm(self, realm_name):
        cmd_name = 'create realm "{realm}"'.format(realm=realm_name)
        url = URL_REALMS.format(server=self.server)

        params = {'enabled': True,
                  'id': realm_name,
                  'realm': realm_name,
                  }

        self._log_rest_request(cmd_name, url, params)
        response = self.session.post(url, json=params)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.created:
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def delete_realm(self, realm_name):
        cmd_name = 'delete realm "{realm}"'.format(realm=realm_name)
        url = URL_REALMS_REALM.format(
            server=self.server, realm=urlquote(realm_name))

        self._log_rest_request(cmd_name, url)
        response = self.session.delete(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.no_content:
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def get_realm_saml_metadata(self, realm_name):
        cmd_name = 'get metadata for realm "{realm}"'.format(realm=realm_name)
        url = URL_REALM_SAML_DESCRIPTOR.format(
            server=self.server, realm=urlquote(realm_name))

        self._log_rest_request(cmd_name, url)
        response = self.session.get(url)
        self._log_rest_response(cmd_name, response)

        if response.status_code != requests.codes.ok:
            raise RESTError(cmd_name, response)

        self._log_return_value(response.text, False)
        return response.text

    def get_clients(self, realm_name):
        cmd_name = 'get clients in realm "{realm}"'.format(realm=realm_name)
        url = URL_CLIENTS.format(
            server=self.server, realm=urlquote(realm_name))

        self._log_rest_request(cmd_name, url)
        response = self.session.get(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json


    def get_client_by_clientid(self, realm_name, clientid):
        cmd_name = 'get clientid "{clientid}" in realm "{realm}"'.format(
            clientid=clientid, realm=realm_name)
        url = URL_CLIENTS.format(
            server=self.server, realm=urlquote(realm_name))

        params = {'clientId': clientid}

        self._log_rest_request(cmd_name, url)
        response = self.session.get(url, params=params)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        if not isinstance(response_json, list):
            raise TypeError('expected list of client representations'
                            ' but got: {data}'.format(data=response_json))

        if not response_json:
            raise KeyError('{item} not found'.format(item=clientid))

        if len(response_json) > 1:
            raise ValueError('expected list of client representations'
                             ' containing exactly 1 item with'
                             ' clientId={clientId})'
                             ' but got: {data}'.format(data=response_json,
                                                       clientId=clientid))

        self._log_return_value(response_json[0])
        return response_json[0]


    def get_client_id_by_clientid(self, realm_name, clientid):
        client = self.get_client_by_clientid(realm_name, clientid)
        return client.get('id')

    def get_client_descriptor(self, realm_name, metadata):
        cmd_name = 'get client descriptor realm "{realm}"'.format(
            realm=realm_name)
        url = URL_CLIENT_DESCRIPTION_CONVERTER.format(
            server=self.server, realm=urlquote(realm_name))

        headers = {'Content-Type': 'application/xml;charset=utf-8'}

        self._log_rest_request(cmd_name, url, metadata)
        response = self.session.post(url, headers=headers, data=metadata)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def get_client_secret_by_id(self, realm_name, obj_id):
        cmd_name = ('get client secret for client "{id}" in realm "{realm}"'.
                    format(id=obj_id, realm=realm_name))
        url = URL_CLIENT_SECRET.format(
            server=self.server,
            realm=urlquote(realm_name),
            id=urlquote(id))

        self._log_rest_request(cmd_name, url)
        response = self.session.get(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def regenerate_client_secret_by_id(self, realm_name, obj_id):
        cmd_name = ('regenerate client secret for client "{id}" in realm "{realm}"'.
                    format(id=obj_id, realm=realm_name))
        url = URL_CLIENT_SECRET.format(
            server=self.server,
            realm=urlquote(realm_name),
            id=urlquote(obj_id))

        self._log_rest_request(cmd_name, url)
        response = self.session.post(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def create_client_from_descriptor(self, realm_name, descriptor):
        cmd_name = 'create client from descriptor '
        '"{client_id}"in realm "{realm}"'.format(
            client_id=descriptor['clientId'], realm=realm_name)
        url = URL_CLIENTS.format(
            server=self.server, realm=urlquote(realm_name))

        self._log_rest_request(cmd_name, url, descriptor)
        response = self.session.post(url, json=descriptor)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.created:
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)

    def create_client(self, realm_name, metadata):
        logger.debug('create client in realm %s on server %s',
                     realm_name, self.server)
        descriptor = self.get_client_descriptor(realm_name, metadata)
        self.create_client_from_descriptor(realm_name, descriptor)
        return descriptor

    def register_client(self, initial_access_token, realm_name, metadata):
        cmd_name = 'register_client realm "{realm}"'.format(
            realm=realm_name)
        url = URL_CLIENT_REGISTRATION_SAML2.format(
            server=self.server, realm=urlquote(realm_name))

        headers = {'Content-Type': 'application/xml;charset=utf-8'}

        if initial_access_token:
            headers['Authorization'] = 'Bearer {token}'.format(
                token=initial_access_token)

        self._log_rest_request(cmd_name, url, metadata)
        response = self.session.post(url, headers=headers, data=metadata)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.created):
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json    # ClientRepresentation

    def delete_client_by_clientid(self, realm_name, clientid):
        obj_id = self.get_client_id_by_clientid(realm_name, clientid)
        self.delete_client_by_id(realm_name, obj_id)


    def delete_client_by_id(self, realm_name, obj_id):
        cmd_name = 'delete client id "{id}"in realm "{realm}"'.format(
            id=obj_id, realm=realm_name)
        url = URL_CLIENTS_ID.format(
            server=self.server,
            realm=urlquote(realm_name),
            id=urlquote(obj_id))

        self._log_rest_request(cmd_name, url)
        response = self.session.delete(url)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.no_content:
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def update_client(self, realm_name, client):
        obj_id = client['id']
        cmd_name = 'update client {clientid} in realm "{realm}"'.format(
            clientid=client['clientId'], realm=realm_name)
        url = URL_CLIENTS_ID.format(
            server=self.server, realm=urlquote(realm_name),
            id=urlquote(obj_id))

        self._log_rest_request(cmd_name, url, client)
        response = self.session.put(url, json=client)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.no_content:
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def update_client_attributes(self, realm_name, client, update_attrs):
        client_id = client['clientId']
        logger.debug('update client attrs: client_id=%s '
                     'current attrs=%s update=%s',
                     client_id, client['attributes'], update_attrs)
        client['attributes'].update(update_attrs)
        logger.debug('update client attrs: client_id=%s '
                     'new attrs=%s', client_id, client['attributes'])
        self.update_client(realm_name, client)


    def update_client_attributes_by_clientid(self, realm_name, clientid,
                                             update_attrs):
        client = self.get_client_by_clientid(realm_name, clientid)
        self.update_client_attributes(realm_name, client, update_attrs)

    def new_saml_group_protocol_mapper(self, mapper_name, attribute_name,
                                       friendly_name=None,
                                       single_attribute=True):
        mapper = {
            'protocol': 'saml',
            'name': mapper_name,
            'protocolMapper': 'saml-group-membership-mapper',
            'config': {
                'attribute.name': attribute_name,
                'attribute.nameformat': 'Basic',
                'single': single_attribute,
                'full.path': False,
            },
        }

        if friendly_name:
            mapper['config']['friendly.name'] = friendly_name

        return mapper

    def create_client_protocol_mapper(self, realm_name, client, mapper):
        obj_id = client['id']
        cmd_name = ('create protocol-mapper "{mapper_name}" for clientid {clientid} '
                    'in realm "{realm}"'.format(
                        mapper_name=mapper['name'],
                        clientid=client['clientId'],
                        realm=realm_name))
        url = URL_CLIENT_PROTOCOL_MAPPER_MODEL.format(
            server=self.server,
            realm=urlquote(realm_name),
            id=urlquote(obj_id))

        self._log_rest_request(cmd_name, url, mapper)
        response = self.session.post(url, json=mapper)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.created:
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def create_client_protocol_mapper_by_clientid(self, realm_name, clientid,
                                                  mapper):
        client = self.get_client_by_clientid(realm_name, clientid)
        self.create_client_protocol_mapper(realm_name, client, mapper)


    def add_client_redirect_uris_by_clientid(self, realm_name, clientid, uris):
        client = self.get_client_by_clientid(realm_name, clientid)

        uris = set(uris)
        redirect_uris = set(client['redirectUris'])
        redirect_uris |= uris
        client['redirectUris'] = list(redirect_uris)
        self.update_client(realm_name, client)

    def remove_client_redirect_uris_by_clientid(self, realm_name, clientid, uris):
        client = self.get_client_by_clientid(realm_name, clientid)

        uris = set(uris)
        redirect_uris = set(client['redirectUris'])
        redirect_uris -= uris
        client['redirectUris'] = list(redirect_uris)

        self.update_client(realm_name, client)


# ------------------------------------------------------------------------------


class KeycloakAdminConnection(KeycloakREST):

    def __init__(self, server, auth_role, realm, client_id,
                 username, password, tls_verify):
        super(KeycloakAdminConnection, self).__init__(server, auth_role)

        self.realm = realm
        self.client_id = client_id
        self.username = username
        self.password = password

        self.session = self._create_session(tls_verify)

    def _create_session(self, tls_verify):
        token_url = URL_OIDC_TOKEN.format(
            server=self.server, realm=urlquote(self.realm))
        refresh_url = token_url

        client = LegacyApplicationClient(client_id=self.client_id)
        session = OAuth2Session(client=client,
                                auto_refresh_url=refresh_url,
                                auto_refresh_kwargs={
                                    'client_id': self.client_id})

        session.verify = tls_verify
        token = session.fetch_token(token_url=token_url,
                                    username=self.username,
                                    password=self.password,
                                    client_id=self.client_id,
                                    verify=session.verify)

        return session


class KeycloakAnonymousConnection(KeycloakREST):

    def __init__(self, server, tls_verify):
        super(KeycloakAnonymousConnection, self).__init__(server, 'anonymous')
        self.session = self._create_session(tls_verify)


    def _create_session(self, tls_verify):
        session = requests.Session()
        session.verify = tls_verify

        return session

# ------------------------------------------------------------------------------


def do_server_info(options, conn):
    server_info = conn.get_server_info()
    print(py_json_pretty(server_info))


def do_list_realms(options, conn):
    realms = conn.get_realms()
    realm_names = get_realm_names_from_realms(realms)
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
    client_ids = get_client_client_ids_from_clients(clients)
    print('\n'.join(sorted(client_ids)))


def do_show_client(options, conn):
    client_rep = conn.get_client_by_clientid(options.realm_name,
                                             options.clientid)
    print(py_json_pretty(client_rep))

def do_get_client_secret(options, conn):
    obj_id = conn.get_client_id_by_clientid(options.realm_name,
                                            options.clientid)
    secret = conn.get_client_secret_by_id(options.realm_name, obj_id)
    print(py_json_pretty(secret))

def do_regenerate_client_secret(options, conn):
    obj_id = conn.get_client_id_by_clientid(options.realm_name,
                                            options.clientid)
    secret = conn.regenerate_client_secret_by_id(options.realm_name, obj_id)
    print(py_json_pretty(secret))

def do_create_client(options, conn):
    metadata = options.metadata.read()
    descriptor = conn.create_client(options.realm_name, metadata)


def do_register_client(options, conn):
    metadata = options.metadata.read()
    client_representation = conn.register_client(
        options.initial_access_token,
        options.realm_name, metadata)


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


class TlsVerifyAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError('nargs not allowed')
        super(TlsVerifyAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values.lower() in ['true', 'yes', 'on']:
            verify = True
        elif values.lower() in ['false', 'no', 'off']:
            verify = False
        else:
            verify = values

        setattr(namespace, self.dest, verify)

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

    parser.add_argument('--tls-verify', action=TlsVerifyAction,
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
                       choices=AUTH_ROLES,
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
    cmd_parser.add_argument('-m', '--metadata', type=argparse.FileType('rb'),
                            required=True,
                            help='SP metadata file or stdin')
    cmd_parser.set_defaults(func=do_create_client)

    # --- client register
    cmd_parser = client_sub_parser.add_parser('register',
                                              help='register new client')
    cmd_parser.add_argument('-m', '--metadata', type=argparse.FileType('rb'),
                            required=True,
                            help='SP metadata file or stdin')
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
    configure_logging(options)

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
        anonymous_conn = KeycloakAnonymousConnection(options.server,
                                                     options.tls_verify)

        admin_conn = KeycloakAdminConnection(options.server,
                                             options.auth_role,
                                             options.admin_realm,
                                             ADMIN_CLIENT_ID,
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
