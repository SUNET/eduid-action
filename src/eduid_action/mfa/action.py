#
# Copyright (c) 2017 NORDUnet A/S
# Copyright (c) 2018 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import json
import pprint
import base64
from flask import current_app, request

from eduid_common.session import session
from eduid_action.common.action_abc import ActionPlugin
from eduid_userdb.credentials import U2F, Webauthn

from u2flib_server.u2f import begin_authentication, complete_authentication

from fido2 import cbor
from fido2.server import RelyingParty, Fido2Server, U2FFido2Server
from fido2.client import ClientData
from fido2.ctap2 import AttestedCredentialData, AuthenticatorData
from fido2.utils import websafe_decode

from . import RESULT_CREDENTIAL_KEY_NAME


__author__ = 'ft'


class Plugin(ActionPlugin):

    PACKAGE_NAME = 'eduid_action.mfa'
    steps = 1

    @classmethod
    def includeme(cls, app):
        mandatory_config_keys = [
            'U2F_APP_ID',
            'U2F_VALID_FACETS',
            'FIDO2_RP_ID',
            'EIDAS_URL',
            'MFA_AUTHN_IDP'
        ]

        for item in mandatory_config_keys:
            if app.config.get(item) is None:
                app.logger.error('The "{}" configuration option is required'.format(item))

        app.config.setdefault('MFA_TESTING', False)

    def get_config_for_bundle(self, action):
        if action.old_format:
            userid = action.user_id
            user = current_app.central_userdb.get_user_by_id(
                userid, raise_on_missing=False)
        else:
            eppn = action.eppn
            user = current_app.central_userdb.get_user_by_eppn(
                eppn, raise_on_missing=False)
        current_app.logger.debug('Loaded User {} from db'.format(user))
        if not user:
            raise self.ActionError('mfa.user-not-found')

        credentials = _get_user_credentials(user)
        current_app.logger.debug('FIDO credentials for user {}:\n{}'.format(user, pprint.pformat(credentials)))

        # CTAP1/U2F
        # TODO: Only make U2F challenges for U2F tokens?
        challenge = None
        if current_app.config.get('GENERATE_U2F_CHALLENGES') is True:
            u2f_tokens = [v['u2f'] for v in credentials.values()]
            try:
                challenge = begin_authentication(current_app.config['U2F_APP_ID'], u2f_tokens)
                current_app.logger.debug('U2F challenge:\n{}'.format(pprint.pformat(challenge)))
            except ValueError:
                # there is no U2F key registered for this user
                pass

        # CTAP2/Webauthn
        # TODO: Only make Webauthn challenges for Webauthn tokens?
        webauthn_credentials = [v['webauthn'] for v in credentials.values()]
        fido2rp = RelyingParty(current_app.config['FIDO2_RP_ID'], 'eduID')
        fido2server = _get_fido2server(credentials, fido2rp)
        raw_fido2data, fido2state = fido2server.authenticate_begin(webauthn_credentials)
        current_app.logger.debug('FIDO2 authentication data:\n{}'.format(pprint.pformat(raw_fido2data)))
        fido2data = base64.urlsafe_b64encode(cbor.dumps(raw_fido2data)).decode('ascii')
        fido2data = fido2data.rstrip('=')

        config = {'u2fdata': '{}', 'webauthn_options': fido2data}

        # Save the challenge to be used when validating the signature in perform_action() below
        if challenge is not None:
            session[self.PACKAGE_NAME + '.u2f.challenge'] = challenge.json
            config['u2fdata'] = json.dumps(challenge.data_for_client)
            current_app.logger.debug(f'FIDO1/U2F challenge for user {user}: {challenge.data_for_client}')

        current_app.logger.debug(f'FIDO2/Webauthn state for user {user}: {fido2state}')
        session[self.PACKAGE_NAME + '.webauthn.state'] = json.dumps(fido2state)

        # Explicit check for boolean True
        if current_app.config.get('MFA_TESTING') is True:
            current_app.logger.info('MFA test mode is enabled')
            config['testing'] = True
        else:
            config['testing'] = False

        # Add config for external mfa auth
        config['eidas_url'] = current_app.config['EIDAS_URL']
        config['mfa_authn_idp'] = current_app.config['MFA_AUTHN_IDP']

        return config

    def perform_step(self, action):
        current_app.logger.debug('Performing MFA step')
        if current_app.config['MFA_TESTING']:
            current_app.logger.debug('Test mode is on, faking authentication')
            return {
                'success': True,
                'testing': True,
            }

        if action.old_format:
            userid = action.user_id
            user = current_app.central_userdb.get_user_by_id(userid, raise_on_missing=False)
        else:
            eppn = action.eppn
            user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=False)
        current_app.logger.debug('Loaded User {} from db (in perform_action)'.format(user))

        # Third party service MFA
        if session.mfa_action.success is True:  # Explicit check that success is the boolean True
            issuer = session.mfa_action.issuer
            authn_instant = session.mfa_action.authn_instant
            authn_context = session.mfa_action.authn_context
            current_app.logger.info('User {} logged in using external mfa service {}'.format(user, issuer))
            action.result = {
                'success': True,
                'issuer': issuer,
                'authn_instant': authn_instant,
                'authn_context': authn_context
            }
            current_app.actions_db.update_action(action)
            return action.result

        req_json = request.get_json()
        if not req_json:
            current_app.logger.error('No data in request to authn {}'.format(user))
            raise self.ActionError('mfa.no-request-data')

        # Process POSTed data
        if 'tokenResponse' in req_json:
            # CTAP1/U2F
            token_response = request.get_json().get('tokenResponse', '')
            current_app.logger.debug('U2F token response: {}'.format(token_response))

            challenge = session.get(self.PACKAGE_NAME + '.u2f.challenge')
            current_app.logger.debug('Challenge: {!r}'.format(challenge))

            device, counter, touch = complete_authentication(challenge, token_response,
                                                             current_app.config['U2F_VALID_FACETS'])
            current_app.logger.debug('U2F authentication data: {}'.format({
                'keyHandle': device['keyHandle'],
                'touch': touch,
                'counter': counter,
            }))

            for this in user.credentials.filter(U2F).to_list():
                if this.keyhandle == device['keyHandle']:
                    current_app.logger.info('User {} logged in using U2F token {} (touch: {}, counter {})'.format(
                        user, this, touch, counter))
                    action.result = {'success': True,
                                     'touch': touch,
                                     'counter': counter,
                                     RESULT_CREDENTIAL_KEY_NAME: this.key,
                                     }
                    current_app.actions_db.update_action(action)
                    return action.result
        elif 'authenticatorData' in req_json:
            # CTAP2/Webauthn
            req = {}
            for this in ['credentialId', 'clientDataJSON', 'authenticatorData', 'signature']:
                try:
                    req_json[this] += ('=' * (len(req_json[this]) % 4))
                    req[this] = base64.urlsafe_b64decode(req_json[this])
                except:
                    current_app.logger.error('Failed to find/b64decode Webauthn parameter {}: {}'.format(
                        this, req_json.get(this)))
                    raise self.ActionError('mfa.bad-token-response')  # XXX add bad-token-response to frontend
            current_app.logger.debug('Webauthn request after decoding:\n{}'.format(pprint.pformat(req)))
            client_data = ClientData(req['clientDataJSON'])
            auth_data = AuthenticatorData(req['authenticatorData'])

            credentials = _get_user_credentials(user)
            fido2state = json.loads(session[self.PACKAGE_NAME + '.webauthn.state'])

            rp_id = current_app.config['FIDO2_RP_ID']
            fido2rp = RelyingParty(rp_id, 'eduID')
            fido2server = _get_fido2server(credentials, fido2rp)
            matching_credentials = [(v['webauthn'], k) for k,v in credentials.items()
                                    if v['webauthn'].credential_id == req['credentialId']]

            if not matching_credentials:
                current_app.logger.error('Could not find webauthn credential {} on user {}'.format(
                    req['credentialId'], user))
                raise self.ActionError('mfa.unknown-token')

            authn_cred = fido2server.authenticate_complete(
                fido2state,
                [mc[0] for mc in matching_credentials],
                req['credentialId'],
                client_data,
                auth_data,
                req['signature'],
            )
            current_app.logger.debug('Authenticated Webauthn credential: {}'.format(authn_cred))

            cred_key = [mc[1] for mc in matching_credentials][0]

            touch = auth_data.flags
            counter = auth_data.counter
            current_app.logger.info('User {} logged in using Webauthn token {} (touch: {}, counter {})'.format(
                user, cred_key, touch, counter))
            action.result = {'success': True,
                             'touch': auth_data.is_user_present() or auth_data.is_user_verified(),
                             'user_present': auth_data.is_user_present(),
                             'user_verified': auth_data.is_user_verified(),
                             'counter': counter,
                             RESULT_CREDENTIAL_KEY_NAME: cred_key,
                             }
            current_app.actions_db.update_action(action)
            return action.result

        else:
            current_app.logger.error('Neither U2F nor Webauthn data in request to authn {}'.format(user))
            current_app.logger.debug('Request: {}'.format(req_json))
            raise self.ActionError('mfa.no-token-response')

        raise self.ActionError('mfa.unknown-token')


def _get_user_credentials(user):
    res = {}
    for this in user.credentials.filter(U2F).to_list():
        acd = AttestedCredentialData.from_ctap1(websafe_decode(this.keyhandle),
                                                websafe_decode(this.public_key))
        res[this.key] = {'u2f': {'version': this.version,
                                 'keyHandle': this.keyhandle,
                                 'publicKey': this.public_key,
                                 },
                         'webauthn': acd,
                         'app_id': this.app_id,
                         }
    for this in user.credentials.filter(Webauthn).to_list():
        keyhandle = this.keyhandle
        cred_data = base64.urlsafe_b64decode(this.credential_data.encode('ascii'))
        credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
        version = 'webauthn'
        res[this.key] = {'u2f': {'version': version,
                                 'keyHandle': keyhandle,
                                 'publicKey': credential_data.public_key,
                                 },
                         'webauthn': credential_data,
                         'app_id': '',
                         }
    return res

def _get_fido2server(credentials, fido2rp):
    # See if any of the credentials is a legacy U2F credential with an app-id
    # (assume all app-ids are the same - authenticating with a mix of different
    # app-ids isn't supported in current Webauthn)
    app_id = None
    for k, v in credentials.items():
        if v['app_id']:
            app_id = v['app_id']
            break
    if app_id:
        return U2FFido2Server(app_id, fido2rp)
    return Fido2Server(fido2rp)
