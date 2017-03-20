#! /usr/bin/env python
"""minimal PyPI like server for use with pip/easy_install"""

import functools
import hashlib
import io
import itertools
import logging
import mimetypes
import os
import re
import sys
from collections import Iterable

import pkg_resources

from . import __version__


log = logging.getLogger(__name__)


class Configuration(object):
    """
    .. see:: config-options: :func:`pypiserver.configure()`
    """

    DEFAULT_SERVER = "auto"
    FALLBACK_HASH_ALGORITHMS = (
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'
    )

    def __init__(
            self,
            root=None,
            host="0.0.0.0",
            port=8080,
            server=DEFAULT_SERVER,
            redirect_to_fallback=True,
            fallback_url="http://pypi.python.org/simple",
            authenticated=None,
            password_file=None,
            overwrite=False,
            hash_algo='md5',
            verbosity=1,
            log_file=None,
            log_frmt="%(asctime)s|%(name)s|%(levelname)s|%(thread)d|%(message)s",
            log_req_frmt="%(bottle.request)s",
            log_res_frmt="%(status)s",
            log_err_frmt="%(body)s: %(exception)s \n%(traceback)s",
            welcome_file=None,
            cache_control=None,
            auther=None,
            VERSION=__version__):
        """Instantiate a configuration object

        Any provided kwargs will override the default values above.
        """
        self.root = root
        self.host = host
        self.port = port
        self.server = server
        self.redirect_to_fallback = redirect_to_fallback
        self.fallback_url = fallback_url
        self.authenticated = authenticated
        self.password_file = password_file
        self.overwrite = overwrite
        self.hash_algo = hash_algo
        self.verbosity = verbosity
        self.log_file = log_file
        self.log_frmt = log_frmt
        self.log_req_frmt = log_req_frmt
        self.log_res_frmt = log_res_frmt
        self.log_err_frmt = log_err_frmt
        self.welcome_file = welcome_file
        self.cache_control = cache_control
        self.auther = auther
        self.VERSION = VERSION

        self.roots = []
        self.welcome_msg = None

        log.info("+++Pypiserver invoked with: %s", self)

        self._populate()

        log.info("+++Pypiserver started with: %s", self)

    def __repr__(self, *args, **kwargs):
        return 'Configuration(**%s)' % self.__dict__

    def __str__(self, *args, **kwargs):
        return 'Configuration:\n%s' % '\n'.join(
            '%20s = %s' % (k, v) for k, v in
            sorted(self.__dict__.items()) if k != 'welcome_msg'
        )

    def update(self, props):
        log.debug('updating config with %s', props)
        d = props if isinstance(props, dict) else vars(props)
        for k, v in d.items():
            setattr(self, k, v)
        self._populate()
        log.debug('updated config: %s', self)

    def validate(self):
        """Run validation methods"""
        log.debug('validating config')
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if attr_name.startswith('_validate_') and callable(attr):
                log.debug('running validation method %s', attr_name)
                attr()

    def _populate(self):
        """Run population methods"""
        log.debug('populating config')
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if attr_name.startswith('_populate_') and callable(attr):
                log.debug('running population method %s', attr_name)
                attr()

    def _populate_authenticated(self):
        """Populate the ``authenticated`` list if necessary"""
        if self.authenticated is None:
            self.authenticated = ['update']

    def _populate_auther(self):
        """Validate the auther attribute"""
        if not callable(self.auther):
            if self.password_file and self.password_file != '.':
                from passlib.apache import HtpasswdFile
                ht_passwd_file = HtpasswdFile(self.password_file)
            else:
                self.password_file = ht_passwd_file = None
            self.auther = functools.partial(
                auth_by_htpasswd_file, ht_passwd_file
            )

    def _populate_roots(self):
        """Populate the ``roots`` attr based on ``root``"""
        if self.root is None:
            self.root = os.path.expanduser("~/packages")

        if isinstance(self.root, (list, tuple)):
            roots = self.root
        else:
            roots = [self.root]

        roots = [os.path.abspath(r) for r in roots]
        self.roots = roots

    def _populate_welcome_msg(self):
        """Populate the ``welcome_msg`` attribute from ``welcome_file``"""
        if not self.welcome_file:
            self.welcome_file = "welcome.html"
            self.welcome_msg = pkg_resources.resource_string(
                __name__, "welcome.html").decode("utf-8")
        else:
            try:
                with io.open(self.welcome_file, 'r', encoding='utf-8') as fd:
                    self.welcome_msg = fd.read()
            except (OSError, IOError):
                log.warning(
                    "Could not load welcome-file(%s)!",
                    self.welcome_file,
                    exc_info=1
                )

    def _validate_authenticated(self):
        """Validate methods for which auth is reuqired"""
        if (not self.authenticated and self.password_file != '.' or
                self.authenticated and self.password_file == '.'):
            auth_err = (
                "When auth-ops-list is empty (-a=.), password-file (-P=%r) "
                "must also be empty ('.')!"
            )
            sys.exit(auth_err % self.password_file)

    def _validate_hash_algo(self):
        """Validate any provided hash algorithm"""
        if self.hash_algo:
            try:
                halgos = hashlib.algorithms_available
            except AttributeError:
                halgos = self.FALLBACK_HASH_ALGORITHMS

            if self.hash_algo not in halgos:
                sys.exit(
                    'Hash-algorithm %s not one of: %s' %
                    (self.hash_algo, halgos)
                )

    def _validate_roots(self):
        """Validate the root attribute"""
        for r in self.roots:
            try:
                os.listdir(r)
            except OSError:
                err = sys.exc_info()[1]
                msg = "Error: while trying to list root(%s): %s"
                sys.exit(msg % (r, err))
# def configure(**kwds):
#     """
#     :return: a 2-tuple (Configure, package-list)
#     """
#     c = Configuration(**kwds)
#     log.info("+++Pypiserver invoked with: %s", c)
#
#     if not c.authenticated:
#         c.authenticated = []
#     if not callable(c.auther):
#         if c.password_file and c.password_file != '.':
#             from passlib.apache import HtpasswdFile
#             htPsswdFile = HtpasswdFile(c.password_file)
#         else:
#             c.password_file = htPsswdFile = None
#         c.auther = functools.partial(auth_by_htpasswd_file, htPsswdFile)
#
#     # Read welcome-msg from external file,
#     #     or failback to the embedded-msg (ie. in standalone mode).
#     #
#     try:
#         if not c.welcome_file:
#             c.welcome_file = "welcome.html"
#             c.welcome_msg = pkg_resources.resource_string(  # @UndefinedVariable
#                 __name__, "welcome.html").decode("utf-8")  # @UndefinedVariable
#         else:
#             with io.open(c.welcome_file, 'r', encoding='utf-8') as fd:
#                 c.welcome_msg = fd.read()
#     except Exception:
#         log.warning(
#             "Could not load welcome-file(%s)!", c.welcome_file, exc_info=1)
#
#     if c.fallback_url is None:
#         c.fallback_url = "http://pypi.python.org/simple"
#
#     if c.hash_algo:
#         try:
#             halgos = hashlib.algorithms_available
#         except AttributeError:
#             halgos = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
#
#         if c.hash_algo not in halgos:
#             sys.exit('Hash-algorithm %s not one of: %s' % (c.hash_algo, halgos))
#
#     log.info("+++Pypiserver started with: %s", c)
#
#     return c


class Packages(object):
    """Minimal class defining a callable interface for packages"""

    def __init__(self, config=None):
        # type: (Configuration) -> None
        """Ensure package routes are readable and iterable"""
        if config is None:
            self._roots = ()
            self.root = None
            return

        self._roots = config.roots
        self.root = config.roots[0]

    def __call__(self):
        # type: () -> Iterable
        """Return a list of packages in the given roots"""
        pkgs = itertools.chain(*(listdir(r) for r in self._roots))
        log.debug('Returning package list: %s', pkgs)
        return pkgs


def auth_by_htpasswd_file(htpasswd_file, username, password):
    """The default ``config.auther``."""
    if htpasswd_file is not None:
        htpasswd_file.load_if_changed()
        return htpasswd_file.check_password(username, password)


mimetypes.add_type("application/octet-stream", ".egg")
mimetypes.add_type("application/octet-stream", ".whl")
mimetypes.add_type("text/plain", ".asc")


# ### Next 2 functions adapted from :mod:`distribute.pkg_resources`.
#
component_re = re.compile(r'(\d+ | [a-z]+ | \.| -)', re.I | re.VERBOSE)
replace = {'pre': 'c', 'preview': 'c', '-': 'final-', 'rc': 'c', 'dev': '@'}.get


def _parse_version_parts(s):
    for part in component_re.split(s):
        part = replace(part, part)
        if part in ['', '.']:
            continue
        if part[:1] in '0123456789':
            yield part.zfill(8)  # pad for numeric comparison
        else:
            yield '*' + part

    yield '*final'  # ensure that alpha/beta/candidate are before final


def parse_version(s):
    parts = []
    for part in _parse_version_parts(s.lower()):
        if part.startswith('*'):
            # remove trailing zeros from each series of numeric parts
            while parts and parts[-1] == '00000000':
                parts.pop()
        parts.append(part)
    return tuple(parts)

# # # # -- End of distribute's code.


_archive_suffix_rx = re.compile(
    r"(\.zip|\.tar\.gz|\.tgz|\.tar\.bz2|-py[23]\.\d-.*|"
    "\.win-amd64-py[23]\.\d\..*|\.win32-py[23]\.\d\..*|\.egg)$",
    re.I)
wheel_file_re = re.compile(
    r"""^(?P<namever>(?P<name>.+?)-(?P<ver>\d.*?))
    ((-(?P<build>\d.*?))?-(?P<pyver>.+?)-(?P<abi>.+?)-(?P<plat>.+?)
    \.whl|\.dist-info)$""",
    re.VERBOSE)
_pkgname_re = re.compile(r'-\d+[a-z_.!+]', re.I)
_pkgname_parts_re = re.compile(
    r"[\.\-](?=cp\d|py\d|macosx|linux|sunos|solaris|irix|aix|cygwin|win)",
    re.I)


def _guess_pkgname_and_version_wheel(basename):
    m = wheel_file_re.match(basename)
    if not m:
        return None, None
    name = m.group("name")
    ver = m.group("ver")
    build = m.group("build")
    if build:
        return name, ver + "-" + build
    else:
        return name, ver


def guess_pkgname_and_version(path):
    path = os.path.basename(path)
    if path.endswith(".asc"):
        path = path.rstrip(".asc")
    if path.endswith(".whl"):
        return _guess_pkgname_and_version_wheel(path)
    if not _archive_suffix_rx.search(path):
        return
    path = _archive_suffix_rx.sub('', path)
    if '-' not in path:
        pkgname, version = path, ''
    elif path.count('-') == 1:
        pkgname, version = path.split('-', 1)
    elif '.' not in path:
        pkgname, version = path.rsplit('-', 1)
    else:
        pkgname = _pkgname_re.split(path)[0]
        ver_spec = path[len(pkgname) + 1:]
        parts = _pkgname_parts_re.split(ver_spec)
        version = parts[0]
    return pkgname, version


def normalize_pkgname(name):
    """Perform PEP 503 normalization"""
    return re.sub(r"[-_.]+", "-", name).lower()


def is_allowed_path(path_part):
    p = path_part.replace("\\", "/")
    return not (p.startswith(".") or "/." in p)


class PkgFile(object):

    __slots__ = ['fn', 'root', '_fname_and_hash',
                 'relfn', 'relfn_unix',
                 'pkgname_norm',
                 'pkgname',
                 'version',
                 'parsed_version',
                 'replaces']

    def __init__(self, pkgname, version, fn=None, root=None, relfn=None, replaces=None):
        self.pkgname = pkgname
        self.pkgname_norm = normalize_pkgname(pkgname)
        self.version = version
        self.parsed_version = parse_version(version)
        self.fn = fn
        self.root = root
        self.relfn = relfn
        self.relfn_unix = None if relfn is None else relfn.replace("\\", "/")
        self.replaces = replaces

    def __repr__(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            ", ".join(["%s=%r" % (k, getattr(self, k))
                                  for k in sorted(self.__slots__)]))

    def fname_and_hash(self, hash_algo):
        if not hasattr(self, '_fname_and_hash'):
            if hash_algo:
                self._fname_and_hash = '%s#%s=%.32s' % (self.relfn_unix, hash_algo,
                                                        digest_file(self.fn, hash_algo))
            else:
                self._fname_and_hash = self.relfn_unix
        return self._fname_and_hash


def _listdir(root):
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [x for x in dirnames if is_allowed_path(x)]
        for x in filenames:
            fn = os.path.join(root, dirpath, x)
            if not is_allowed_path(x) or not os.path.isfile(fn):
                continue
            res = guess_pkgname_and_version(x)
            if not res:
                # #Seems the current file isn't a proper package
                continue
            pkgname, version = res
            if pkgname:
                yield PkgFile(pkgname=pkgname,
                              version=version,
                              fn=fn, root=root,
                              relfn=fn[len(root) + 1:])


def find_packages(pkgs, prefix=""):
    prefix = normalize_pkgname(prefix)
    for x in pkgs:
        if prefix and x.pkgname_norm != prefix:
            continue
        yield x


def get_prefixes(pkgs):
    normalized_pkgnames = set()
    for x in pkgs:
        if x.pkgname:
            normalized_pkgnames.add(x.pkgname_norm)
    return normalized_pkgnames


def exists(root, filename):
    assert "/" not in filename
    dest_fn = os.path.join(root, filename)
    return os.path.exists(dest_fn)


def store(root, filename, save_method):
    assert "/" not in filename
    dest_fn = os.path.join(root, filename)
    save_method(dest_fn, overwrite=True)  # Overwite check earlier.


def _digest_file(fpath, hash_algo):
    """
    Reads and digests a file according to specified hashing-algorith.

    :param str sha256: any algo contained in :mod:`hashlib`
    :return: <hash_algo>=<hex_digest>

    From http://stackoverflow.com/a/21565932/548792
    """
    blocksize = 2**16
    digester = getattr(hashlib, hash_algo)()
    with open(fpath, 'rb') as f:
        for block in iter(lambda: f.read(blocksize), b''):
            digester.update(block)
    return digester.hexdigest()[:32]


try:
    from .cache import cache_manager

    def listdir(root):
        # root must be absolute path
        return cache_manager.listdir(root, _listdir)

    def digest_file(fpath, hash_algo):
        # fpath must be absolute path
        return cache_manager.digest_file(fpath, hash_algo, _digest_file)

except ImportError:
    listdir = _listdir
    digest_file = _digest_file
