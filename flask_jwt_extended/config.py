import datetime
from warnings import warn

from flask_jwt_extended.utils import get_jwt_manager

# Older versions of pyjwt do not have the requires_cryptography set. Also,
# older versions will not be adding new algorithms to them, so I can hard code
# the default version here and be safe. If there is a newer algorithm someone
# wants to use, they will need newer versions of pyjwt and it will be included
# in their requires_cryptography set, and if they attempt to use it in older
# versions of pyjwt, it will kick it out as an unrecognized algorithm.
try:
    from jwt.algorithms import requires_cryptography
except ImportError:  # pragma: no cover
    requires_cryptography = {'RS256', 'RS384', 'RS512', 'ES256', 'ES384',
                             'ES521', 'ES512', 'PS256', 'PS384', 'PS512'}


def build_config(**override_options):
    jwt_manager = get_jwt_manager()
    config_options = jwt_manager.get_config_dictionary()

    for key, value in override_options.items():
        if key not in config_options:
            raise RuntimeError(
                "{} is not a valid flask-jwt-extended option".format(key)
            )
        config_options[key] = value

    return _Config(config_options)


class _Config(object):
    """
    Helper object for accessing and verifying options in this extension. This
    is meant for internal use of the application; modifying config options
    should be done with flasks ```app.config``` or kwargs to functions.

    Default values for the configuration options are set in the jwt_manager
    object. All of these values are read only.
    """

    def __init__(self, config_options):
        self.config_options = config_options

    @property
    def is_asymmetric(self):
        return self.algorithm in requires_cryptography

    @property
    def encode_key(self):
        return self._private_key if self.is_asymmetric else self._secret_key

    @property
    def decode_key(self):
        return self._public_key if self.is_asymmetric else self._secret_key

    @property
    def token_location(self):
        locations = self.config_options['jwt_token_location']
        if not isinstance(locations, list):
            locations = [locations]
        for location in locations:
            if location not in ('headers', 'cookies'):
                raise RuntimeError('JWT_TOKEN_LOCATION can only contain '
                                   '"headers" and/or "cookies"')
        return locations

    @property
    def jwt_in_cookies(self):
        return 'cookies' in self.token_location

    @property
    def jwt_in_headers(self):
        return 'headers' in self.token_location

    @property
    def header_name(self):
        name = self.config_options['jwt_header_name']
        if not name:
            raise RuntimeError("JWT_ACCESS_HEADER_NAME cannot be empty")
        return name

    @property
    def header_type(self):
        return self.config_options['jwt_header_type']

    @property
    def access_cookie_name(self):
        return self.config_options['jwt_access_cookie_name']

    @property
    def refresh_cookie_name(self):
        return self.config_options['jwt_refresh_cookie_name']

    @property
    def access_cookie_path(self):
        return self.config_options['jwt_access_cookie_path']

    @property
    def refresh_cookie_path(self):
        return self.config_options['jwt_refresh_cookie_path']

    @property
    def cookie_secure(self):
        return self.config_options['jwt_cookie_secure']

    @property
    def cookie_domain(self):
        return self.config_options['jwt_cookie_domain']

    @property
    def session_cookie(self):
        return self.config_options['jwt_session_cookie']

    @property
    def csrf_protect(self):
        return self.jwt_in_cookies and self.config_options['jwt_cookie_csrf_protect']

    @property
    def csrf_request_methods(self):
        return self.config_options['jwt_csrf_methods']

    @property
    def csrf_in_cookies(self):
        return self.config_options['jwt_csrf_in_cookies']

    @property
    def access_csrf_cookie_name(self):
        return self.config_options['jwt_access_csrf_cookie_name']

    @property
    def refresh_csrf_cookie_name(self):
        return self.config_options['jwt_refresh_csrf_cookie_name']

    @property
    def access_csrf_cookie_path(self):
        return self.config_options['jwt_access_csrf_cookie_path']

    @property
    def refresh_csrf_cookie_path(self):
        return self.config_options['jwt_refresh_csrf_cookie_path']

    def _get_depreciated_csrf_header_name(self):
        # This used to be the same option for access and refresh header names.
        # This gives users a warning if they are still using the old behavior
        old_name = self.config_options.get('jwt_csrf_header_name', None)
        if old_name:
            msg = (
                "JWT_CSRF_HEADER_NAME is depreciated. Use JWT_ACCESS_CSRF_HEADER_NAME "
                "or JWT_REFRESH_CSRF_HEADER_NAME instead"
            )
            warn(msg, DeprecationWarning)
        return old_name

    @property
    def access_csrf_header_name(self):
        return self._get_depreciated_csrf_header_name() or \
               self.config_options['jwt_access_csrf_header_name']

    @property
    def refresh_csrf_header_name(self):
        return self._get_depreciated_csrf_header_name() or \
               self.config_options['jwt_refresh_csrf_header_name']

    @property
    def access_expires(self):
        delta = self.config_options['jwt_access_token_expires']
        if not isinstance(delta, datetime.timedelta):
            raise RuntimeError('JWT_ACCESS_TOKEN_EXPIRES must be a datetime.timedelta')
        return delta

    @property
    def refresh_expires(self):
        delta = self.config_options['jwt_refresh_token_expires']
        if not isinstance(delta, datetime.timedelta):
            raise RuntimeError('JWT_REFRESH_TOKEN_EXPIRES must be a datetime.timedelta')
        return delta

    @property
    def algorithm(self):
        return self.config_options['jwt_algorithm']

    @property
    def blacklist_enabled(self):
        return self.config_options['jwt_blacklist_enabled']

    @property
    def blacklist_checks(self):
        check_type = self.config_options['jwt_blacklist_token_checks']
        if not isinstance(check_type, list):
            check_type = [check_type]
        for item in check_type:
            if item not in ('access', 'refresh'):
                raise RuntimeError('JWT_BLACKLIST_TOKEN_CHECKS must be "access" or "refresh"')
        return check_type

    @property
    def blacklist_access_tokens(self):
        return 'access' in self.blacklist_checks

    @property
    def blacklist_refresh_tokens(self):
        return 'refresh' in self.blacklist_checks

    @property
    def _secret_key(self):
        # TODO this breaks with new config. Make sure we have a unit test for
        #      this and that it is fixed by putting the flask secret key in the
        #      config options as needed.
        key = self.config_options['jwt_secret_key']
        if not key:
            key = self.config_options.get('secret_key', None)
            if not key:
                raise RuntimeError('JWT_SECRET_KEY or flask SECRET_KEY '
                                   'must be set when using symmetric '
                                   'algorithm "{}"'.format(self.algorithm))
        return key

    @property
    def _public_key(self):
        key = self.config_options['jwt_public_key']
        if not key:
            raise RuntimeError('JWT_PUBLIC_KEY must be set to use '
                               'asymmetric cryptography algorithm '
                               '"{}"'.format(self.algorithm))
        return key

    @property
    def _private_key(self):
        key = self.config_options['jwt_private_key']
        if not key:
            raise RuntimeError('JWT_PRIVATE_KEY must be set to use '
                               'asymmetric cryptography algorithm '
                               '"{}"'.format(self.algorithm))
        return key

    @property
    def cookie_max_age(self):
        # Returns the appropiate value for max_age for flask set_cookies. If
        # session cookie is true, return None, otherwise return a number of
        # seconds a long ways in the future
        return None if self.session_cookie else 2147483647  # 2^31

    @property
    def identity_claim(self):
        return self.config_options['jwt_identity_claim']

    @property
    def user_claims(self):
        return self.config_options['jwt_user_claims']
