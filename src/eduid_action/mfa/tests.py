# -*- coding: utf8 -*-#

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
from datetime import datetime
from bson import ObjectId
from copy import deepcopy
from mock import patch
from eduid_userdb.userdb import User
from eduid_userdb.credentials import U2F
from eduid_userdb.testing import MOCKED_USER_STANDARD
from eduid_action.common.testing import MockIdPApp
from eduid_action.common.testing import ActionsTestCase
from eduid_action.mfa.action import Plugin
from eduid_action.mfa.idp import add_actions
from eduid_userdb.exceptions import UserDoesNotExist

__author__ = 'ft'

MFA_ACTION = {
        '_id': ObjectId('234567890123456789012301'),
        'eppn': MOCKED_USER_STANDARD['eduPersonPrincipalName'],
        'action': 'mfa',
        'session': 'mock-session',
        'preference': 1,
        'params': {}
        }

class MockTicket:
    def __init__(self, key):
        self.key = key
        self.mfa_action_creds = {}


class MFAActionPluginTests(ActionsTestCase):

    def setUp(self):
        super(MFAActionPluginTests, self).setUp()
        u2f = U2F(version='U2F_V2',
                  app_id='test_app_id',
                  keyhandle='test_key_handle',
                  public_key='test_public_key',
                  attest_cert='test_attest_cert',
                  description='test_description',
                  )
        self.user.credentials.add(u2f)
        self.app.central_userdb.save(self.user, check_sync=False)

    def update_actions_config(self, config):
        config['MFA_TESTING'] = False
        config['ACTION_PLUGINS'].append('mfa')
        config['U2F_APP_ID'] = 'https://example.com'
        config['U2F_VALID_FACETS'] = [
            'https://dashboard.dev.eduid.se',
            'https://idp.dev.eduid.se']
        config['FIDO2_RP_ID'] = 'idp.example.com'
        return config

    def test_get_mfa_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    mock_idp_app = MockIdPApp(self.app.actions_db)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.authenticate(client, sess, idp_session='mock-session')
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['action'], True)
                    self.assertEquals(data['url'], 
                            'http://example.com/bundles/eduid_action.mfa-bundle.dev.js')
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 1)

    def test_get_mfa_action_wrong_session(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    mock_idp_app = MockIdPApp(self.app.actions_db)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.authenticate(client, sess, idp_session='wrong-session')
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['action'], False)
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 1)

    def test_get_mfa_action_no_db(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    mock_idp_app = MockIdPApp(None)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.authenticate(client, sess, idp_session='mock-session')
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['action'], False)
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 0)

    def test_get_mfa_action_no_u2f_token(self):
        u2f_tokens = self.user.credentials.filter(U2F).to_list()
        for token in u2f_tokens:
            self.user.credentials.remove(token.key)
            self.app.central_userdb.save(self.user, check_sync=False)
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    mock_idp_app = MockIdPApp(self.app.actions_db)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.authenticate(client, sess, idp_session='mock-session')
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['action'], False)
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 0)

    def test_get_config(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    mock_idp_app = MockIdPApp(self.app.actions_db)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.authenticate(client, sess, idp_session='mock-session')
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    response = client.get('/config')
                    data = json.loads(response.data)
                    u2f_data = json.loads(data['payload']['u2fdata'])
                    self.assertEquals(u2f_data["registeredKeys"][0]["keyHandle"], "test_key_handle")
                    self.assertEquals(u2f_data["registeredKeys"][0]["version"], "U2F_V2")
                    self.assertEquals(u2f_data["appId"], "https://example.com")
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 1)

    def test_get_config_no_user(self):
        self.app.central_userdb.remove_user_by_id(self.user.user_id)
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    mock_idp_app = MockIdPApp(self.app.actions_db)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.authenticate(client, sess, idp_session='mock-session')
                    with self.assertRaises(UserDoesNotExist):
                        client.get('/get-actions')

    def test_action_no_token_response(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare(sess, Plugin, 'mfa', action_dict=MFA_ACTION)
                with self.app.test_request_context():
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token})
                    response = client.post('/post-action', data=data,
                            content_type=self.content_type_json)
                    self.assertEquals(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['message'], "mfa.no-token-response")
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 1)

    @patch('eduid_action.mfa.action.complete_authentication')
    def test_action_wrong_keyhandle(self, mock_complete_authn):
        mock_complete_authn.return_value = ({'keyHandle': 'wrong-handle'},
                'dummy-touch', 'dummy-counter')
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare(sess, Plugin, 'mfa', action_dict=MFA_ACTION)
                with self.app.test_request_context():
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token,
                                       'tokenResponse': 'dummy-response'})
                    response = client.post('/post-action', data=data,
                            content_type=self.content_type_json)
                    self.assertEquals(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['message'], "mfa.unknown-token")
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 1)

    @patch('eduid_action.mfa.action.complete_authentication')
    def test_action_success(self, mock_complete_authn):
        mock_complete_authn.return_value = ({'keyHandle': 'test_key_handle'},
                'dummy-touch', 'dummy-counter')
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare(sess, Plugin, 'mfa', action_dict=MFA_ACTION)
                with self.app.test_request_context():
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token,
                                       'tokenResponse': 'dummy-response'})
                    response = client.post('/post-action', data=data,
                            content_type=self.content_type_json)
                    self.assertEquals(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['message'], "actions.action-completed")

    @patch('eduid_action.mfa.action.complete_authentication')
    def test_action_back_to_idp(self, mock_complete_authn):
        mock_complete_authn.return_value = ({'keyHandle': 'test_key_handle'},
                'dummy-touch', 'dummy-counter')
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare(sess, Plugin, 'mfa', action_dict=MFA_ACTION)
                with self.app.test_request_context():
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token,
                                       'tokenResponse': 'dummy-response'})
                    response = client.post('/post-action', data=data,
                            content_type=self.content_type_json)
                    self.assertEquals(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 1)
                    mock_idp_app = MockIdPApp(self.app.actions_db)
                    add_actions(mock_idp_app, self.user,
                            MockTicket('mock-session'))
                    self.assertEquals(len(self.app.actions_db.get_actions(self.user.eppn,
                        'mock-session')), 0)
