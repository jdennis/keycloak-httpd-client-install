from __future__ import print_function
import argparse
import base64
import copy
import grp
from collections import namedtuple
import logging
import os
import pwd
import random
import re
import json
import shutil
import sys
import subprocess
import tempfile

import six
from six.moves.urllib.parse import quote as urlquote
from six.moves.urllib.parse import urlsplit, urlunsplit, urlparse

from lxml import etree

# -------------------------------- Constants ----------------------------------

DEV_NULL = '/dev/null'
BIN_TIMEOUT = '/usr/bin/timeout'

SAML_PAOS_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS'

LOG_FILE_ROTATION_COUNT = 3
STEP = logging.INFO + 1

# -------------------------------- Variables ----------------------------------

logger = logging.getLogger(__name__)

# ---------------------------- Logging Utilities ------------------------------

def _add_step_logger():
    class StepLogger(logging.Logger):

        def __init__(self, name):
            self.step_number = 1
            super(StepLogger, self).__init__(name)

        def step(self, msg, *args, **kwargs):
            if self.isEnabledFor(STEP):
                self._log(STEP, ('[Step %2d] ' % self.step_number) + msg,
                          args, **kwargs)
                self.step_number += 1

    logging.addLevelName(STEP, 'STEP')
    logging.setLoggerClass(StepLogger)

def configure_logging(options, add_step_logger=False):
    if add_step_logger:
        _add_step_logger()

    log_dir = os.path.dirname(options.log_file)
    if not log_dir:
        log_dir = '.'
    if os.path.exists(log_dir):
        if not os.path.isdir(log_dir):
            raise ValueError('logging directory "{log_dir}" exists but is not '
                             'directory'.format(log_dir=log_dir))
    else:
        os.makedirs(log_dir)

    # Check if log exists and should therefore be rolled
    need_roll = os.path.isfile(options.log_file)

    if add_step_logger:
        log_level = STEP
    else:
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

    root_logger = logging.getLogger()

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            options.log_file, mode='w', backupCount=LOG_FILE_ROTATION_COUNT)
    except IOError as e:
        print('Unable to open log file %s (%s)' % (options.log_file, e),
              file=sys.stderr)

    else:
        formatter = logging.Formatter(
            '%(asctime)s %(name)s %(levelname)s: %(message)s')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)

        if need_roll:
            file_handler.doRollover()

    console_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Set the log level on the logger to the lowest level
    # possible. This allows the message to be emitted from the logger
    # to it's handlers where the level will be filtered on a per
    # handler basis.
    root_logger.setLevel(1)

# ------------------------------ JSON Utilities -------------------------------

def json_pretty(text):
    return json.dumps(json.loads(text),
                      indent=4, sort_keys=True)


def py_json_pretty(py_json):
    return json_pretty(json.dumps(py_json))


# ------------------------------ Path Utilities -------------------------------

def join_path(*args):
    '''Join each argument into a final path assuring there is
    exactly one slash separating all components in the final path
    and there are no leading or trailing spaces between path components.
    Initial or final slashes are preserved but are collapsed into a
    single slash.

    Why not use posixpath.join and posixpath.normpath? Because they do not
    handle multiple slashes, leading and trailing slashes the way we want'''

    if not args:
        return ''

    components = []

    for item in args:
        components.extend(item.split('/'))

    if components[0]:
        leading_slash = False
    else:
        leading_slash = True

    if components[-1]:
        trailing_slash = False
    else:
        trailing_slash = True

    components = [x.strip() for x in components if x]

    path = '/'.join(components)

    if leading_slash:
        path = '/' + path

    if trailing_slash and components:
        path = path + '/'

    return path

def generate_random_string(n_bits=48):
    '''
    Return a random string to be used as a secret.

    This implementation creates a string of hexadecimal digits.
    There is no guarantee of uniqueness.

    parameters:
      n_bits
        number of bits of random data, will be rounded to next
        highest multiple of 4
    :returns:
        string of random hexadecimal digits
    '''
    # round up to multiple of 4
    n_bits = (n_bits + 3) & ~3
    random_string = '%0*x' % (n_bits >> 2, random.getrandbits(n_bits))
    return random_string

try:
    from os.path import commonpath
except ImportError:
    # os.path.commonpath first appeared in Python 3.5
    # If our version of Python does not have it use this simplified but almost
    # identical version that is compatible with 2.7 <= Python <= 3.5
    def commonpath(paths):
        """Given a sequence of path names, returns the longest common sub-path."""

        if not paths:
            raise ValueError('commonpath() arg is an empty sequence')

        if isinstance(paths[0], bytes):
            sep = b'/'
            curdir = b'.'
        else:
            sep = '/'
            curdir = '.'

        split_paths = [path.split(sep) for path in paths]

        try:
            isabs, = set(p[:1] == sep for p in paths)
        except ValueError:
            raise ValueError("Can't mix absolute and relative paths")

        split_paths = [[c for c in s if c and c != curdir] for s in split_paths]
        s1 = min(split_paths)
        s2 = max(split_paths)
        common = s1
        for i, c in enumerate(s1):
            if c != s2[i]:
                common = s1[:i]
                break

        prefix = sep if isabs else sep[:0]
        return prefix + sep.join(common)

def is_path_antecedent(ancestor, antecedent):
    'True if antecedent path is below the ancestor path'
    ancestor = os.path.normpath(ancestor)
    antecedent = os.path.normpath(antecedent)
    if ancestor == antecedent:
        return False
    common = commonpath((ancestor, antecedent))
    return ancestor == common

# -------------------------- Shell Command Utilities --------------------------


def nolog_replace(string, nolog):
    """Replace occurences of strings given in `nolog` with XXXXXXXX"""
    for value in nolog:
        if not isinstance(value, six.string_types):
            continue

        quoted = urlquote(value)
        shquoted = shell_quote(value)
        for nolog_value in (shquoted, value, quoted):
            string = string.replace(nolog_value, 'XXXXXXXX')
    return string


def shell_quote(string):
    return "'" + string.replace("'", "'\\''") + "'"


def run_cmd(args, stdin=None, raiseonerr=True,
            nolog=(), env=None, capture_output=True, skip_output=False,
            cwd=None, runas=None, timeout=None, suplementary_groups=None):
    """
    Execute a command and return stdin, stdout and the process return code.

    :param args: List of arguments for the command
    :param stdin: Optional input to the command
    :param raiseonerr: If True, raises an exception if the return code is
        not zero
    :param nolog: Tuple of strings that shouldn't be logged, like passwords.
        Each tuple consists of a string to be replaced by XXXXXXXX.

        Example:
        We have a command
            [paths.SETPASSWD, '--password', 'Secret123', 'someuser']
        and we don't want to log the password so nolog would be set to:
        ('Secret123',)
        The resulting log output would be:

        /usr/bin/setpasswd --password XXXXXXXX someuser

        If a value isn't found in the list it is silently ignored.
    :param env: Dictionary of environment variables passed to the command.
        When None, current environment is copied
    :param capture_output: Capture stderr and stdout
    :param skip_output: Redirect the output to /dev/null and do not capture it
    :param cwd: Current working directory
    :param runas: Name of a user that the command should be run as. The spawned
        process will have both real and effective UID and GID set.
    :param timeout: Timeout if the command hasn't returned within the specified
        number of seconds.
    :param suplementary_groups: List of group names that will be used as
        suplementary groups for subporcess.
        The option runas must be specified together with this option.
    """
    if suplementary_groups is None:
        suplementary_groups = []

    assert isinstance(suplementary_groups, list)
    p_in = None
    p_out = None
    p_err = None

    if isinstance(nolog, six.string_types):
        # We expect a tuple (or list, or other iterable) of nolog strings.
        # Passing just a single string is bad: strings are also, so this
        # would result in every individual character of that string being
        # replaced by XXXXXXXX.
        # This is a sanity check to prevent that.
        raise ValueError('nolog must be a tuple of strings.')

    if env is None:
        # copy default env
        env = copy.deepcopy(os.environ)
        env['PATH'] = (
            '/bin:/sbin:/usr/kerberos/bin:'
            '/usr/kerberos/sbin:/usr/bin:/usr/sbin')
    if stdin:
        p_in = subprocess.PIPE
    if skip_output:
        p_out = p_err = open(DEV_NULL, 'w')
    elif capture_output:
        p_out = subprocess.PIPE
        p_err = subprocess.PIPE

    if timeout:
        # If a timeout was provided, use the timeout command
        # to execute the requested command.
        args[0:0] = [BIN_TIMEOUT, str(timeout)]

    arg_string = nolog_replace(' '.join(shell_quote(a) for a in args), nolog)
    logger.debug('Starting external process')
    logger.debug('args=%s', arg_string)

    def preexec():
        os.setgroups(suplementary_gids),
        os.setregid(pent.pw_gid, pent.pw_gid),
        os.setreuid(pent.pw_uid, pent.pw_uid),

    preexec_fn = None
    if runas is not None:
        pent = pwd.getpwnam(runas)

        suplementary_gids = [
            grp.getgrnam(group).gr_gid for group in suplementary_groups
        ]

        logger.debug('runas=%s (UID %d, GID %s)', runas,
                     pent.pw_uid, pent.pw_gid)
        if suplementary_groups:
            for group, gid in zip(suplementary_groups, suplementary_gids):
                logger.debug('suplementary_group=%s (GID %d)', group, gid)

        preexec_fn = preexec
    try:
        p = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                             close_fds=True, env=env, cwd=cwd,
                             preexec_fn=preexec_fn)
        stdout, stderr = p.communicate(stdin)
        stdout, stderr = str(stdout), str(stderr)    # Make pylint happy
    except KeyboardInterrupt:
        logger.debug('Process interrupted')
        p.wait()
        raise
    except:
        logger.debug('Process execution failed')
        raise
    finally:
        if skip_output:
            p_out.close()   # pylint: disable=E1103

    if timeout and p.returncode == 124:
        logger.debug('Process did not complete before timeout')

    logger.debug('Process finished, return code=%s', p.returncode)

    # The command and its output may include passwords that we don't want
    # to log. Replace those.
    if capture_output and not skip_output:
        stdout = nolog_replace(stdout, nolog)
        stderr = nolog_replace(stderr, nolog)
        logger.debug('stdout=%s', stdout)
        logger.debug('stderr=%s', stderr)

    if p.returncode != 0 and raiseonerr:
        raise subprocess.CalledProcessError(p.returncode, arg_string, stdout)

    return (stdout, stderr, p.returncode)


# --------------------------- Keycloak Data Utilities --------------------------


def get_realm_names_from_realms(realms):
    return [x['realm'] for x in realms]


def get_client_client_ids_from_clients(clients):
    return [x['clientId'] for x in clients]


def install_file(src_file, dst_file):
    logger.debug('install_file dst_file="%s"', dst_file)
    if os.path.exists(dst_file):
        if not os.path.isfile(dst_file):
            raise ValueError('install file "{dst_file}" exists but is not '
                             'plain file'.format(dst_file=dst_file))
        dst_backup_file = dst_file + '.orig'
        if not os.path.exists(dst_backup_file):
            os.rename(dst_file, dst_backup_file)
    shutil.copy(src_file, dst_file)


def install_file_from_data(data, dst_file):
    logger.debug('install_file_from_data dst_file="%s"', dst_file)
    if os.path.exists(dst_file):
        if not os.path.isfile(dst_file):
            raise ValueError('install file "{dst_file}" exists but is not '
                             'plain file'.format(dst_file=dst_file))
        dst_backup_file = dst_file + '.orig'
        if not os.path.exists(dst_backup_file):
            os.rename(dst_file, dst_backup_file)
    with open(dst_file, 'w') as f:
        f.write(data)


def load_data_from_file(filename):
    logger.debug('load data from file "%s"', filename)
    with open(filename, 'r') as f:
        data = f.read()
    return data

def mkdir(pathname, mode=0o775):
    logger.debug('mkdir pathname="%s" mode=%#o', pathname, mode)
    if os.path.exists(pathname):
        if not os.path.isdir(pathname):
            raise ValueError('mkdir "{pathname}" exists but is not '
                             'directory'.format(pathname=pathname))
    else:
        os.makedirs(pathname, mode)


def httpd_restart():
    cmd = ['/usr/bin/systemctl', 'restart', 'httpd.service']
    run_cmd(cmd)

# ----------------------------- HTTP Utilities --------------------------------

def server_name_from_url(url):
    return urlparse(url).netloc

def normalize_url(url, default_scheme='https'):
    '''Assure scheme and port are canonical.

    SAML requires a scheme for URL's, if a scheme is not present add a
    default scheme.

    Strip the port from the URL if it matches the scheme (e.g. 80 for
    http and 443 for https)

    Explicitly specifying a default port (e.g. http://example.com:80
    or https://example.com:443) will cause Mellon to fail. This occurs
    because the port gets embedded into the location URL for each
    endpoint in the SP metadata (e.g the Assertion Consumer
    Service). The IdP sets the Destination attribute in the SAML
    response by looking it up in the SP metadata, thus the Destination
    will have the default port in it (e.g. 443). Upon receiving the
    SAML response the SP compares the URL of the request to the
    Destination attribute in the SAML response, they must match for
    the response to be considered valid. However when Mellon asks
    Apache what the request URL was it won't have the port in it thus
    the URL comparison fails. So why is the port absent? It turns out
    that most (all?) browsers will strip the port from a URL if it
    matches the port for the scheme (e.g. 80 for http and 443 for
    https). Thus even if you include the port in the URL it will never
    be included in the URL the browser emits. This also includes
    stripping the port from the HTTP host header (which Apache uses to
    reconstruct the URL).
    '''

    s = urlsplit(url)
    scheme = s.scheme
    netloc = s.netloc
    path = s.path
    query = s.query
    fragment = s.fragment
    hostname = s.hostname
    port = s.port

    if not scheme:
        scheme = default_scheme

    if port is not None:
        if scheme == 'http' and port == 80:
            port = None
        elif scheme == 'https' and port == 443:
            port = None

    if port is None:
        netloc = hostname
    else:
        netloc = '%s:%d' % (hostname, port)

    return urlunsplit((scheme, netloc, path, query, fragment))

# ------------------------------ PEM Utilities --------------------------------


class InvalidBase64Error(ValueError):
    pass

pem_headers = {
    'csr': 'NEW CERTIFICATE REQUEST',
    'cert': 'CERTIFICATE',
    'crl': 'CRL',
    'cms': 'CMS',
    'key': 'PRIVATE KEY',
}

PEMParseResult = namedtuple('PEMParseResult',
                            ['pem_type',
                             'pem_start', 'pem_end',
                             'base64_start', 'base64_end', 'base64_text',
                             'binary_data'])

pem_begin_re = re.compile(r'^-{5}BEGIN\s+([^-]+)-{5}\s*$', re.MULTILINE)
pem_end_re = re.compile(r'^-{5}END\s+([^-]+)-{5}\s*$', re.MULTILINE)


def pem_search(text, start=0):
    '''Search for a block of PEM formatted data

    Search for a PEM block in a text string. The search begins at
    start. If a PEM block is found a PEMParseResult named tuple is
    returned, otherwise if no PEM block is found None is returned.

    The PEMParseResult named tuple is:
    (pem_type, pem_start, pem_end, base64_start, base64_end)

    pem_type
        The text following '-----BEGIN ' in the PEM header.
        Common examples are 'CERTIFICATE', 'CRL', 'CMS'.
    pem_start, pem_end
        The beginning and ending positions of the PEM block
        including the PEM header and footer.
    base64_start, base64_end
        The beginning and ending positions of the base64 text
        contained inside the PEM header and footer.
    base64_text
        The base64 text (e.g. text[b.base64_start : b.base64_end])
    binary_data
        The decoded base64 text. None if not decoded.

    If the pem_type is not the same in both the header and footer
    a ValueError is raised.

    The start and end positions are suitable for use as slices into
    the text. To search for multiple PEM blocks pass pem_end as the
    start position for the next iteration. Terminate the iteration
    when None is returned. Example:

        start = 0
        while True:
            b = pem_search(text, start)
            if b is None:
                break
            start = b.pem_end

    :param string text: the text to search for PEM blocks
    :param int start: the position in text to start searching from
    :returns: PEMParseResult named tuple or None if not found
    '''

    match = pem_begin_re.search(text, pos=start)
    if match:
        pem_start = match.start()
        begin_text = match.group(0)
        base64_start = min(len(text), match.end() + 1)
        begin_pem_type = match.group(1).strip()

        match = pem_end_re.search(text, pos=base64_start)
        if match:
            pem_end = min(len(text), match.end() + 1)
            base64_end = match.start() - 1
            end_pem_type = match.group(1).strip()
        else:
            raise ValueError('failed to find end matching "%s"' % begin_text)

        if begin_pem_type != end_pem_type:
            raise ValueError('beginning & end PEM types do not match '
                             '(%s != %s)' %
                             (begin_pem_type, end_pem_type))
    else:
        return None

    pem_type = begin_pem_type
    base64_text = text[base64_start:base64_end]
    try:
        binary_data = base64.b64decode(base64_text)
    except Exception as e:
        binary_data = None
        raise InvalidBase64Error('failed to base64 decode %s PEM '
                                 'at position %d: %s' %
                                 (pem_type, pem_start, e))

    result = PEMParseResult(pem_type=pem_type,
                            pem_start=pem_start, pem_end=pem_end,
                            base64_start=base64_start, base64_end=base64_end,
                            base64_text=base64_text,
                            binary_data=binary_data)
    return result


def parse_pem(text, pem_type=None, max_items=None):
    '''Scan text for PEM data, return list of PEMParseResult

    pem_type operates as a filter on the type of PEM desired. If
    pem_type is specified only those PEM blocks which match will be
    included. The pem_type is a logical name, not the actual text in
    the pem header (e.g. 'cert'). If the pem_type is None all PEM
    blocks are returned.

    If max_items is specified the result is limited to that number of
    items.

    The return value is a list of PEMParseResult named tuples.  The
    PEMParseResult provides complete information about the PEM block
    including the decoded binary data for the PEM block.  The list is
    ordered in the same order as found in the text.

    Examples:

        # Get all certs
        certs = parse_pem(text, 'cert')

        # Get the first cert
        try:
            binary_cert = parse_pem(text, 'cert', 1)[0].binary_data
        except IndexError:
            raise ValueError('no cert found')

    :param string text: The text to search for PEM blocks
    :param string pem_type: Only return data for this pem_type.
                            Valid types are: csr, cert, crl, cms, key.
                            If pem_type is None no filtering is performed.
    :param int max_items: Limit the number of blocks returned.
    :returns: List of PEMParseResult, one for each PEM block found
    '''

    pem_blocks = []
    start = 0

    while True:
        b = pem_search(text, start)
        if b is None:
            break
        start = b.pem_end
        if pem_type is None:
            pem_blocks.append(b)
        else:
            try:
                if pem_headers[pem_type] == b.pem_type:
                    pem_blocks.append(b)
            except KeyError:
                raise ValueError('unknown pem_type: %s' % (pem_type))

        if max_items is not None and len(pem_blocks) >= max_items:
            break

    return pem_blocks

# ------------------------- SAML Metadata Utilities ---------------------------

def get_sp_assertion_consumer_url(metadata_file, entity_id=None,
                                  binding=None):
    '''Retrieve AssertionConsumerURL(s) from SP metadata

    Read and parse the SAML metadata contained in metadata_file.

    If the entity_id is supplied then select the SP matching it,
    this is useful when the metadata contains multiple SP's. If the
    entity_id is not supplied then there must be exactly 1 SP in the
    metadata, that one will be selected.

    If the SAML endpoint binding is supplied then only
    AssertionConsumerServiceURL's matching that binding will be returned,
    otherwise all AssertionConsumerURL's will be returned.

    The return value is a list of AssertionConsumerServiceURL's in the order
    found in the metadata.

    :param metadata_file:        Pathname of SAML Metadata file
    :param entity_id (optional): EntityID of SP
    :param binding (optional):   Filter matching this binding
    :return:                     List of AssertionConsumerServiceURL's
    '''

    namespaces = dict(md='urn:oasis:names:tc:SAML:2.0:metadata',
                      saml='urn:oasis:names:tc:SAML:2.0:assertion',
                      ds='http://www.w3.org/2000/09/xmldsig#')

    root = etree.parse(metadata_file).getroot()

    if True or not entity_id:
        # If entity_id was not supplied locate a unique SPSSODescriptor
        xpath = ('//md:EntityDescriptor/md:SPSSODescriptor')
        sp = root.xpath(xpath, namespaces=namespaces)
        if not sp:
            raise ValueError('entity_id not supplied and no '
                             'SPSSODescriptor was found')
        elif len(sp) > 1:
            raise ValueError('entity_id not supplied and multiple '
                             'SPSSODescriptor elements were found')

        xpath = ('ancestor::md:EntityDescriptor')
        ed = sp[0].xpath(xpath, namespaces=namespaces)

        entity_id = ed[0].attrib['entityID']

    else:
        xpath = ('//md:EntityDescriptor[@entityID="{entity_id}"]'
                 '/md:SPSSODescriptor'.format(entity_id=entity_id))

        sp = root.xpath(xpath, namespaces=namespaces)
        if not sp:
            raise IndexError('SPSSODescriptor with EntityID="{entity_id}" '
                             'not found'.format(entity_id=entity_id))
        elif len(sp) > 1:
            raise ValueError('multiple SPSSODescriptor with '
                             'EntityID="{entity_id}" found'.format(
                                 entity_id=entity_id))
    sp = sp[0]

    if not binding:
        xpath = 'md:AssertionConsumerService'
        acs = sp.xpath(xpath, namespaces=namespaces)
        urls = [x.attrib['Location'] for x in acs]
    else:
        xpath = 'md:AssertionConsumerService[@Binding="{binding}"]'.format(
            binding=SAML_PAOS_BINDING)
        acs = sp.xpath(xpath, namespaces=namespaces)
        urls = [x.attrib['Location'] for x in acs]

    return urls


def get_entity_id_from_metadata(metadata_file, role):
    '''Retrieve entityID from metadata

    Read and parse the SAML metadata contained in metadata_file,
    search for one of the following roles and return the entityID
    associated with that role.

    SSO Identity Provider (role='idp')
    SSO Service Provider (role='sp')
    Authentication Authority (role='authn_authority')
    Attribute Authority (role='attr_authority)
    Policy Decision Point (role='pdp')

    :param metadata_file:        Pathname of SAML Metadata file
    :param role:                 one of: idp, sp, authn_authority,
                                 attr_authority, pdp
    :return:                     entityID
    '''

    roles = {'idp':             'IDPSSODescriptor',
             'sp':              'SPSSODescriptor',
             'authn_authority': 'AuthnAuthorityDescriptor',
             'attr_authority':  'AttributeAuthorityDescriptor',
             'pdp':             'PDPDescriptor'}


    role_descriptor = roles.get(role)
    if role_descriptor is None:
        raise ValueError('invalid role "%s", must be one of: %s' %
                         (role, ', '.join(sorted(roles.keys()))))

    namespaces = dict(md='urn:oasis:names:tc:SAML:2.0:metadata',
                      saml='urn:oasis:names:tc:SAML:2.0:assertion',
                      ds='http://www.w3.org/2000/09/xmldsig#')

    root = etree.parse(metadata_file).getroot()

    xpath = '//md:EntityDescriptor/md:%s' % role_descriptor
    entity = root.xpath(xpath, namespaces=namespaces)
    if not entity:
        raise ValueError('no %s found' % role_descriptor)
    elif len(entity) > 1:
        raise ValueError('multiple EntityDescriptor elements found')

    xpath = ('ancestor::md:EntityDescriptor')
    ed = entity[0].xpath(xpath, namespaces=namespaces)

    entity_id = ed[0].attrib['entityID']
    return entity_id

# -------------------- Certificate Creation & Installation --------------------


def load_cert_from_file(filename, data_format='base64_text'):
    '''Load a cert from a file, return as either base64 text or binary.

    :param string filename: The input file to read the cert from.
    :param string data_format: One of: 'base64_text', 'binary'
    :returns: cert in requested format
    '''
    with open(filename, 'r') as f:
        data = f.read()

    certs = parse_pem(data, 'cert')

    if not certs:
        raise ValueError('No cert found in {filename}'.format(
            filename=filename))

    if len(certs) > 1:
        raise ValueError('Multiple certs ({num_certs}) '
                         'found in {filename}'.format(
                             num_certs=len(certs),
                             filename=filename))

    if data_format == 'base64_text':
        return certs[0].base64_text
    if data_format == 'binary':
        return certs[0].binary

    raise ValueError('Uknown data_format "{data_format}"'.format(
        data_format=data_format))


def generate_cert(subject):
    '''Generate self-signed cert and key.

    A new self-signed cert and key is generated.
    The key and cert are returned as strings in PEM format.

    :param string subject: Certificate subject.
    :returns: key, cert as 2-tuple of PEM formatted strings
    '''

    tmpdir = tempfile.mkdtemp()
    key_file = os.path.join(tmpdir, 'key.pem')
    cert_file = os.path.join(tmpdir, 'cert.pem')
    try:
        openssl_subject = '/CN=%s' % subject
        cmd = ['openssl',
               'req', '-x509', '-batch', '-days', '1825',
               '-newkey', 'rsa:2048', '-nodes', '-subj', openssl_subject,
               '-keyout', key_file, '-out', cert_file]

        run_cmd(cmd)

        with open(key_file, 'r') as f:
            key = f.read()

        with open(cert_file, 'r') as f:
            cert = f.read()

    finally:
        shutil.rmtree(tmpdir)

    return key, cert


def install_mellon_cert(options):
    if options.mellon_key_file or options.mellon_cert_file:
        if not (options.mellon_key_file and options.mellon_cert_file):
            raise ValueError('You must specify both a cert and key file, '
                             'not just one.')
        install_file(options.mellon_key_file, options.mellon_dst_key_file)
        install_file(options.mellon_cert_file, options.mellon_dst_cert_file)
    else:
        subject = options.client_hostname
        key, cert = generate_cert(subject)
        install_file_from_data(key, options.mellon_dst_key_file)
        install_file_from_data(cert, options.mellon_dst_cert_file)

#---------------------------- Argparse Utilities -------------------------------

class DeprecatedStoreAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super(DeprecatedStoreAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print('option "%s" DEPRECATED: %s\n' % (option_string, self.help),
              file=sys.stderr)
        setattr(namespace, self.dest, values)

def _argparse_copy_items(items):
    if items is None:
        return []
    # The copy module is used only in the 'append' and 'append_const'
    # actions, and it is needed only when the default value isn't a list.
    # Delay its import for speeding up the common case.
    if isinstance(items, list):
        return items[:]
    return copy.copy(items)

class DeprecatedAppendAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super(DeprecatedAppendAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print('option "%s" DEPRECATED: %s\n' % (option_string, self.help),
              file=sys.stderr)
        items = getattr(namespace, self.dest, None)
        items = _argparse_copy_items(items)
        items.append(values)
        setattr(namespace, self.dest, items)

class UniqueNamesAction(argparse.Action):
    '''Store into dest a set of names.
    The option may be specified multiple times to build up the set.
    Or the argument value may contain multiple names seperated by commas and/or spaces.
    Or a combination of either of the above. For example:

    --foo a --foo b --foo c
    --foo 'a b c'
    --foo 'a, b, c'
    --foo a --foo 'b c'

    All produce namespace.foo={'a', 'b', 'c'}

    If you wish to limit the name to a set of valid names subclass this class
    and set the class attribute name_choices to a list or set of names.
    The name_choices class attribute plays the same role as choices but we can't use
    choices because the test for membership in the choices list occurs before
    names are split and we can't use nargs because you end up with a set of lists.
    '''
    name_choices = set()
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError('nargs not allowed')
        super(UniqueNamesAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is None:
            setattr(namespace, self.dest, set())
        for value in re.split('[ \t,]+', values):
            value = value.strip()
            if not value:
                continue
            if self.name_choices:
                if value not in self.name_choices:
                    args = {'value': value,
                            'choices': ', '.join(map(repr, self.name_choices))}
                    msg = 'invalid choice: %(value)r (choose from %(choices)s)'
                    raise argparse.ArgumentError(self, msg % args)

            getattr(namespace, self.dest).add(value)

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
