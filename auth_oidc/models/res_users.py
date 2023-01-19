# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging

import requests

from odoo import api, models
from odoo.exceptions import AccessDenied
from odoo.http import request
import jwt
import time
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
        if oauth_provider.client_secret:
            auth = (oauth_provider.client_id, oauth_provider.client_secret)
        if(oauth_provider.sign_private_key_jwt):
            private_key_jwt = self.create_private_key_jwt(oauth_provider)
            scope = ""
            payload = f'grant_type=client_credentials&scope={scope}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={private_key_jwt}'
            response = requests.post(
                oauth_provider.token_endpoint,
                data={payload},
                auth=auth,
            )
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

    def create_private_key_jwt(oauth_provider):
        client_id = oauth_provider.client_id
        auth_url = oauth_provider.token_url
        
        private_key = {
                "kty": "EC",
                "d": "YKczdWXvYgMdTNhW0RNl4mLZU_X9OYGUfBiiqEKCHt4",
                "use": "sig",
                "crv": "P-256",
                "x": "9pJxCuEE4ojs8G03RMHrM7UFxnEXRaj4_crzHMGhihM",
                "y": "tMJIsglmPcG8kvdBUjBpKWO38kaLSIyAdHQmSktWtE4",
                "alg": "ES256"
            }
        token = jwt.encode({
            'iss': client_id,
            'sub': client_id,
            'aud': auth_url,
            "exp": int(time.time()) + 3600
        },
        private_key,
        algorithm='RS256',
        )
        return token    
    def _auth_oauth_get_tokens_private_key_jwt(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        code = params.get("code")
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        auth = None
        if oauth_provider.client_secret:
            auth = (oauth_provider.client_id, oauth_provider.client_secret)
        response = requests.post(
            oauth_provider.token_endpoint,
            data=dict(
                client_id=oauth_provider.client_id,
                grant_type="authorization_code",
                code=code,
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion="", # TODO
                redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
            ),
            auth=auth,
        )
        response.raise_for_status()
        response_json = response.json()
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        return response_json.get("access_token"), response_json.get("id_token")

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
        elif oauth_provider.flow == "private_key_jwt":
            access_token, id_token = self._auth_oauth_get_tokens_private_key_jwt(
                oauth_provider, params
            )
        else:
            return super(ResUsers, self).auth_oauth(provider, params)
        if not access_token:
            _logger.error("No access_token in response.")
            raise AccessDenied()
        if not id_token:
            _logger.error("No id_token in response.")
            raise AccessDenied()
        validation = oauth_provider._parse_id_token(id_token, access_token)
        # required check
        if not validation.get("user_id"):
            _logger.error("user_id claim not found in id_token (after mapping).")
            raise AccessDenied()
        # retrieve and sign in user
        params["access_token"] = access_token
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)
