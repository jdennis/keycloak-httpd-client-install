import inspect
import logging
from oauthlib.oauth2 import LegacyApplicationClient
import requests
from requests_oauthlib import OAuth2Session

from six.moves.urllib.parse import quote as urlquote

from keycloak_httpd_client import utils

# -------------------------------- Constants ----------------------------------

ADMIN_CLIENT_ID = 'admin-cli'
AUTH_ROLES = ['root-admin', 'realm-admin', 'anonymous']

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
URL_CLIENT_REGISTRATION_DEFAULT = (
    '{server}/auth/realms/{realm}/clients-registrations/default')
URL_CLIENT_REGISTRATION_SAML2 = (
    '{server}/auth/realms/{realm}/clients-registrations/saml2-entity-descriptor')
URL_CLIENT_REGISTRATION_OIDC = (
    '{server}/auth/realms/{realm}/clients-registrations/openid-connect')

URL_CLIENT_PROTOCOL_MAPPER_MODEL = (
    '{server}/auth/admin/realms/{realm}/clients/{id}/protocol-mappers/models')


CONTENT_TYPE_JSON = 'application/json;charset=utf-8'
CONTENT_TYPE_XML = 'application/xml;charset=utf-8'

# -------------------------------- Variables ----------------------------------

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class RESTError(Exception):
    def __init__(self, cmd_name, response):
        super(RESTError, self).__init__()
        self.cmd_name = cmd_name
        self.status_code = response.status_code
        self.status_reason = response.reason
        try:
            self.response_json = response.json()
        except ValueError:
            self.response_json = None
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

        logger.debug(self.message)
        self.args = (self.message,)

    def __str__(self):
        return self.message

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
            value = utils.py_json_pretty(return_value)
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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

        if response.status_code != requests.codes.created: # pylint: disable=no-member
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

        if response.status_code != requests.codes.no_content: # pylint: disable=no-member
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

        if response.status_code != requests.codes.ok: # pylint: disable=no-member
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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

    def convert_saml_metadata_to_client_representation(self, realm_name, metadata):
        cmd_name = 'get client descriptor realm "{realm}"'.format(
            realm=realm_name)
        url = URL_CLIENT_DESCRIPTION_CONVERTER.format(
            server=self.server, realm=urlquote(realm_name))

        headers = {'Content-Type': CONTENT_TYPE_XML}

        self._log_rest_request(cmd_name, url, metadata)
        response = self.session.post(url, headers=headers, data=metadata)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
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
                response.status_code != requests.codes.ok): # pylint: disable=no-member
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)
        return response_json

    def create_client_from_client_representation(self, realm_name, client_representation):
        cmd_name = ('create client from client representation in '
                    'realm "{realm}"'.format(realm=realm_name))
        url = URL_CLIENTS.format(
            server=self.server, realm=urlquote(realm_name))

        headers = {'Content-Type': CONTENT_TYPE_JSON}

        self._log_rest_request(cmd_name, url, client_representation)
        response = self.session.post(url, headers=headers,
                                     data=client_representation)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if response.status_code != requests.codes.created: # pylint: disable=no-member
            raise RESTError(cmd_name, response)

        self._log_return_value(response_json)

    def create_client_from_saml_metadata(self, realm_name, saml_metadata):
        logger.debug('create client in realm %s on server %s',
                     realm_name, self.server)
        client_representation = \
            self.convert_saml_metadata_to_client_representation(realm_name,
                                                                saml_metadata)
        self.create_client_from_client_representation(realm_name,
                                                      client_representation)
        return client_representation

    def register_client(self, initial_access_token, realm_name,
                        client_data_format, client_data):
        cmd_name = ('register_client realm "{realm}" using client data format '
                    '"{client_data_format}"'.format(
                        realm=realm_name,
                        client_data_format=client_data_format))

        if client_data_format == 'default':
            template = URL_CLIENT_REGISTRATION_DEFAULT
            content_type = CONTENT_TYPE_JSON
        elif client_data_format == 'oidc':
            template = URL_CLIENT_REGISTRATION_OIDC
            content_type = CONTENT_TYPE_JSON
        elif client_data_format == 'saml2':
            template = URL_CLIENT_REGISTRATION_SAML2
            content_type = CONTENT_TYPE_XML
        else:
            raise ValueError('Unknown client data format: "%s"' %
                             client_data_format)

        url = template.format(
            server=self.server, realm=urlquote(realm_name))

        headers = {'Content-Type': content_type}

        if initial_access_token:
            headers['Authorization'] = 'Bearer {token}'.format(
                token=initial_access_token)

        self._log_rest_request(cmd_name, url, client_data)
        response = self.session.post(url, headers=headers,
                                     data=client_data)
        self._log_rest_response(cmd_name, response)

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        if (not response_json or
                response.status_code != requests.codes.created): # pylint: disable=no-member
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

        if response.status_code != requests.codes.no_content: # pylint: disable=no-member
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

        if response.status_code != requests.codes.no_content: # pylint: disable=no-member
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

        if response.status_code != requests.codes.created: # pylint: disable=no-member
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
