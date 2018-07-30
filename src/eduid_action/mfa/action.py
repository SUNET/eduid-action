#
# Copyright (c) 2017 NORDUnet A/S
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
from flask import current_app, request

from eduid_action.common.action_abc import ActionPlugin
from eduid_userdb.credentials import U2F

from u2flib_server.u2f import begin_authentication, complete_authentication


__author__ = 'ft'


class Plugin(ActionPlugin):

    PACKAGE_NAME = 'eduid_action.mfa'
    steps = 1

    @classmethod
    def includeme(cls, app):

        for item in ('u2f_app_id',
                     'u2f_valid_facets'):
            if app.config.get(item) is None:
                app.logger.error('The "{}" configuration option is required'.format(item))

        app.config.setdefault('MFA_TESTING', False)

    def get_config_for_bundle(self, action):
        userid = action.user_id
        user = current_app.central_userdb.get_user_by_id(userid, raise_on_missing=False)
        current_app.logger.debug('Loaded User {} from db'.format(user))
        if not user:
            raise self.ActionError('User not found')

        u2f_tokens = []
        for this in user.credentials.filter(U2F).to_list():
            data = {'version': this.version,
                    'keyHandle': this.keyhandle,
                    'publicKey': this.public_key,
                    #'appId': APP_ID,
                    }
            u2f_tokens.append(data)

        current_app.logger.debug('U2F tokens for user {}: {}'.format(user, u2f_tokens))

        challenge = begin_authentication(current_app.config['u2f_app_id'], u2f_tokens)

        # Save the challenge to be used when validating the signature in perform_action() below
        session[self.PACKAGE_NAME + '.u2f.challenge'] = challenge.json

        current_app.logger.debug('U2F challenge for user {}: {}'.format(user, challenge.data_for_client))

        config = {'u2fdata': json.dumps(challenge.data_for_client)}
        if current_app.config.get('MFA_TESTING', False) == True:
            current_app.logger.info('MFA test mode is enabled')
            config['testing'] = True
        else:
            config['testing'] = False
        return config

    def perform_step(self, action):
        if current_app.config['MFA_TESTING']:
            current_app.logger.debug('Test mode is on, faking authentication')
            return {'success': True,
                   'testing': True,
                   }
        token_response = request.get_json().get('tokenResponse', '')
        if not token_response:
            raise self.ActionError('mfa.no-token-response')

        current_app.logger.debug('U2F token response: {}'.format(token_response))

        challenge = session.get(self.PACKAGE_NAME + '.u2f.challenge')
        current_app.logger.debug("Challenge: {!r}".format(challenge))

        device, counter, touch = complete_authentication(challenge,
                token_response, current_app.config['u2f_valid_facets'])
        current_app.logger.debug('U2F authentication data: {}'.format({
            'keyHandle': device['keyHandle'],
            'touch': touch,
            'counter': counter,
        }))

        userid = action.user_id
        user = current_app.central_userdb.get_user_by_id(userid, raise_on_missing=False)
        current_app.logger.debug('Loaded User {} from db (in perform_action)'.format(user))

        for this in user.credentials.filter(U2F).to_list():
            if this.keyhandle == device['keyHandle']:
                current_app.logger.info('User {} logged in using U2F token {} (touch: {}, counter {})'.format(
                    user, this, touch, counter))
                current_app.actions_db.remove_action_by_id(action.action_id)
                return {'success': True,
                       'touch': touch,
                       'counter': counter,
                       'key_handle': this.keyhandle,
                       }

        raise self.ActionError('mfa.unknown-token')
