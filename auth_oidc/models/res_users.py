# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import base64
import logging
from datetime import datetime, timedelta

import requests

from odoo import api, models
from odoo.exceptions import AccessDenied
from odoo.http import request

try:
    from jose import jwt
except ImportError:
    logging.getLogger(__name__).debug("jose library not installed")

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    def _auth_oauth_get_tokens_implicit_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
        return params.get("access_token"), params.get("id_token")

    def _auth_oauth_get_tokens_auth_code_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        code = params.get("code")
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        auth = None
        if oauth_provider.client_authentication_method == "client_secret":
            auth = (oauth_provider.client_id, oauth_provider.client_secret)
        if oauth_provider.client_authentication_method == "private_key_jwt":
            private_key_jwt = self.create_private_key_jwt(oauth_provider)
            payload = dict(
                client_id=oauth_provider.client_id,
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:"
                + oauth_provider.assertion_type,
                client_assertion=private_key_jwt,
                grant_type="authorization_code",
                code=code,
                code_verifier=oauth_provider.code_verifier,  # PKCE
                redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
            )
            response = requests.post(oauth_provider.token_endpoint, data=payload)
        else:
            response = requests.post(
                oauth_provider.token_endpoint,
                data=dict(
                    client_id=oauth_provider.client_id,
                    grant_type="authorization_code",
                    code=code,
                    code_verifier=oauth_provider.code_verifier,  # PKCE
                    redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
                ),
                auth=auth,
            )
        response.raise_for_status()
        response_json = response.json()
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        return response_json.get("access_token"), response_json.get("id_token")

    def create_private_key_jwt(self, oauth_provider):
        secret = base64.b64decode(
            oauth_provider.with_context(bin_size=False).client_private_key
        )
        client_id = oauth_provider.client_id
        auth_url = oauth_provider.token_endpoint
        token = jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": auth_url,
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
            },
            secret,
            algorithm="RS256",
        )

        return token

    @api.model
    def auth_oauth(self, provider, params):
        oauth_provider = self.env["auth.oauth.provider"].browse(provider)
        if oauth_provider.flow == "id_token":
            access_token, id_token = self._auth_oauth_get_tokens_implicit_flow(
                oauth_provider, params
            )
        elif oauth_provider.flow == "id_token_code":
            access_token, id_token = self._auth_oauth_get_tokens_auth_code_flow(
                oauth_provider, params
            )
        else:
            return super().auth_oauth(provider, params)
        if not access_token:
            _logger.error("No access_token in response.")
            raise AccessDenied()
        if not id_token:
            _logger.error("No id_token in response.")
            raise AccessDenied()
        validation = oauth_provider._parse_id_token(id_token, access_token)
        # required check
        if "sub" in validation and "user_id" not in validation:
            # set user_id for auth_oauth, user_id is not an OpenID Connect standard
            # claim:
            # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
            validation["user_id"] = validation["sub"]
        elif not validation.get("user_id"):
            _logger.error("user_id claim not found in id_token (after mapping).")
            raise AccessDenied()
        # retrieve and sign in user
        params["access_token"] = access_token
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)
