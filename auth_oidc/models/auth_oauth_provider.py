# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging
import secrets

import requests

from odoo import fields, models, tools

try:
    from jose import jwt
except ImportError:
    logging.getLogger(__name__).debug("jose library not installed")


class AuthOauthProvider(models.Model):
    _inherit = "auth.oauth.provider"

    flow = fields.Selection(
        [
            ("access_token", "OAuth2"),
            ("id_token_code", "OpenID Connect (authorization code flow)"),
            ("id_token", "OpenID Connect (implicit flow, not recommended)"),
        ],
        string="Auth Flow",
        required=True,
        default="access_token",
    )
    token_map = fields.Char(
        help="Some Oauth providers don't map keys in their responses "
        "exactly as required.  It is important to ensure user_id and "
        "email at least are mapped. For OpenID Connect user_id is "
        "the sub key in the standard."
    )

    client_authentication_method = fields.Selection(
        [
            ("client_secret", "Client Secret"),
            # ("client_secret_jwt", "Signed Client Secret (JWT)"),
            ("private_key_jwt", "Private Key JWT"),
        ],
        required=True,
        default="client_secret",
    )
    assertion_type = fields.Selection(
        [("jwt-bearer", "JWT Bearer")],
        required=False,
        default="jwt-bearer",
    )

    client_private_key = fields.Binary(string="Private Key")

    client_secret = fields.Char(
        help="Used in OpenID Connect authorization code flow for confidential clients.",
    )

    code_verifier = fields.Char(
        default=lambda self: secrets.token_urlsafe(32), help="Used for PKCE."
    )
    validation_endpoint = fields.Char(required=False)
    token_endpoint = fields.Char(
        string="Token URL", help="Required for OpenID Connect authorization code flow."
    )
    jwks_uri = fields.Char(string="JWKS URL", help="Required for OpenID Connect.")

    extra_authorize_params = fields.Text(
        help="Extra Parameters to be passed to Auth endpoint. "
        'To be given as JSON. Example: {"param":"value"}',
    )

    @tools.ormcache("self.jwks_uri", "kid")
    def _get_key(self, kid):
        r = requests.get(self.jwks_uri)
        r.raise_for_status()
        response = r.json()
        for key in response["keys"]:
            if key["kid"] == kid:
                return key
        return {}

    def _map_token_values(self, res):
        if self.token_map:
            for pair in self.token_map.split(" "):
                from_key, to_key = [k.strip() for k in pair.split(":", 1)]
                if to_key not in res:
                    res[to_key] = res.get(from_key, "")
        return res

    def _parse_id_token(self, id_token, access_token):
        self.ensure_one()
        res = {}
        header = jwt.get_unverified_header(id_token)
        res.update(
            jwt.decode(
                id_token,
                self._get_key(header.get("kid")),
                algorithms=["RS256"],
                audience=self.client_id,
                access_token=access_token,
                options={"verify_at_hash": False},
            )
        )

        res.update(self._map_token_values(res))
        return res
