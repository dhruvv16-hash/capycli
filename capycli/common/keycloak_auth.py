import logging
import time
from datetime import datetime
import jwt
from requests.auth import AuthBase
from sw360 import SW360Keycloak

from capycli.common.print import print_text, print_yellow
from capycli import get_logger

LOG = get_logger(__name__)

class KeycloakAuth(AuthBase):
    def __init__(self, url: str, client_id: str, client_secret: str, write_access: bool, initial_token: str):
        self.kc = SW360Keycloak(url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.write_access = write_access
        self.token = initial_token

    def _refresh_token(self):
        try:
            new_token = self.kc.get_keycloak_token(self.client_id, self.client_secret, self.write_access)
            if new_token:
                self.token = new_token
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("SW360 Keycloak token refreshed successfully.")
                return True
            else:
                print_yellow("  Failed to refresh token: empty token returned")
        except Exception as ex:
            print_yellow("  Failed to refresh token: " + repr(ex))
        return False

    def is_token_expiring_soon(self) -> bool:
        try:
            decoded = jwt.decode(self.token, algorithms=["HS256"], options={"verify_signature": False})
            if "exp" in decoded:
                exp = datetime.fromtimestamp(int(decoded["exp"]))
                # refresh if less than 5 minutes remaining
                return (exp - datetime.now()).total_seconds() < 300
        except Exception:
            pass
        return False

    def __call__(self, r):
        # Refresh token shortly before expiry
        if self.token and self.is_token_expiring_soon():
            self._refresh_token()

        if self.token:
            r.headers['Authorization'] = 'Bearer ' + self.token

        r.register_hook('response', self.handle_401)
        return r

    def handle_401(self, r, **kwargs):
        if r.status_code == 401 and not getattr(r, '_sw360_retried', False):
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Received 401 Unauthorized, attempting token refresh...")
                
            if self._refresh_token():
                # Consume content of response so we can reuse the connection
                r.content
                r.close()
                
                # Create a new request based on the old one
                new_req = r.request.copy()
                new_req.headers['Authorization'] = 'Bearer ' + self.token
                new_req._sw360_retried = True
                
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Retrying request after token refresh.")
                
                _r = r.connection.send(new_req, **kwargs)
                _r.history.append(r)
                _r.request = new_req
                return _r
        return r
