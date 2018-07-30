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
from eduid_userdb.userdb import User
from eduid_userdb.credentials import U2F
from eduid_userdb.testing import MOCKED_USER_STANDARD
from eduid_action.common.testing import MockIdPApp
from eduid_action.common.testing import ActionsTestCase
from eduid_action.mfa.action import Plugin

__author__ = 'ft'

MFA_ACTION = {
        '_id': ObjectId('234567890123456789012301'),
        'user_oid': MOCKED_USER_STANDARD['_id'],
        'action': 'mfa',
        'preference': 1,
        'params': {}
        }


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
        config['MFA_TESTING'] = True
        config['ACTION_PLUGINS'].append('mfa')
        return config

    def test_action_success(self):
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
                    self.assertEquals(data['payload']['message'], "actions.action-completed")
