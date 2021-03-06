# -*- coding: utf8 -*-#

# Copyright (c) 2015 NORDUnet A/S
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
from __future__ import absolute_import

__author__ = 'eperez'


import json
import unittest
from mock import patch
from datetime import datetime
from bson import ObjectId
from eduid_userdb.tou import ToUEvent
from eduid_action.common.testing import MockIdPApp
from eduid_action.common.testing import ActionsTestCase
from eduid_action.tou.action import Plugin
from eduid_action.tou.idp import add_actions


TOU_ACTION = {
        '_id': ObjectId('234567890123456789012301'),
        'eppn': 'hubba-bubba',
        'action': 'tou',
        'preference': 100,
        'params': {
            'version': 'test-version'
            }
        }


class ToUActionPluginTests(ActionsTestCase):

    def setUp(self):
        super(ToUActionPluginTests, self).setUp(init_am=True, am_settings={'ACTION_PLUGINS': ['tou']})
        self.tou_db = self.app.tou_db

    def tearDown(self):
        self.tou_db._drop_whole_collection()
        super(ToUActionPluginTests, self).tearDown()

    def update_actions_config(self, config):
        config['ACTION_PLUGINS'] = ['tou']
        config['INTERNAL_SIGNUP_URL'] = 'http://example.com/signup'
        return config

    def tou_accepted(self, version):
        event_id = ObjectId()
        self.user.tou.add(ToUEvent(
            version=version,
            application='eduid_tou_plugin',
            created_ts=datetime.utcnow(),
            event_id=event_id
            ))
        self.app.central_userdb.save(self.user, check_sync=False)

    def test_get_tou_action(self):
        with self.session_cookie(self.browser) as client:
            with self.app.test_request_context():
                mock_idp_app = MockIdPApp(self.app.actions_db, tou_version='test-version')
                add_actions(mock_idp_app, self.user, None)
                with client.session_transaction() as sess:
                    self.authenticate(client, sess)
                response = client.get('/get-actions')
                self.assertEqual(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEquals(data['action'], True)
                self.assertEquals(data['url'], 'http://example.com/bundles/eduid_action.tou-bundle.dev.js')

    def test_get_tou_action_tou_accepted(self):
        with self.session_cookie(self.browser) as client:
            with self.app.test_request_context():
                mock_idp_app = MockIdPApp(self.app.actions_db, tou_version='test-version')
                self.tou_accepted('test-version')
                add_actions(mock_idp_app, self.user, None)
                with client.session_transaction() as sess:
                    self.authenticate(client, sess)
                response = client.get('/get-actions')
                self.assertEqual(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEquals(data['action'], False)

    def test_get_config(self):
        with self.session_cookie(self.browser) as client:
            with self.app.test_request_context():
                mock_idp_app = MockIdPApp(self.app.actions_db, tou_version='test-version')
                add_actions(mock_idp_app, self.user, None)
                with client.session_transaction() as sess:
                    self.authenticate(client, sess)
                response = client.get('/get-actions')
                self.assertEqual(response.status_code, 200)
                response = client.get('/config')
                data = json.loads(response.data.decode('utf-8'))
                self.assertEquals(data['payload']['tous']['sv'], 'test tou svenska')

    def test_get_config_no_tous(self):
        with self.session_cookie(self.browser) as client:
            with self.app.test_request_context():
                mock_idp_app = MockIdPApp(self.app.actions_db, tou_version='not-existing-version')
                add_actions(mock_idp_app, self.user, None)
                with client.session_transaction() as sess:
                    self.authenticate(client, sess)
                response = client.get('/get-actions')
                self.assertEqual(response.status_code, 200)
                response = client.get('/config')
                data = json.loads(response.data.decode('utf-8'))
                self.assertEquals(data['payload']['message'], 'tou.no-tou')

    @unittest.skip("Fix when celery workers have proper de init or we have a singleton worker")
    def test_get_accept_tou(self):
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'tou', action_dict=TOU_ACTION)
            with self.app.test_request_context():
                # verify the user hasn't previously accepted the test version
                user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
                self.assertFalse(user.tou.has_accepted(TOU_ACTION['params']['version']))

                with client.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                data = json.dumps({'accept': True, 'csrf_token': csrf_token})
                response = client.post('/post-action', data=data, content_type=self.content_type_json)
                self.assertEquals(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEquals(data['payload']['message'], "actions.action-completed")
                # verify the tou is now accepted in the main database
                user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
                self.assertTrue(user.tou.has_accepted(TOU_ACTION['params']['version']))

    def test_get_not_accept_tou(self):
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'tou', action_dict=TOU_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                data = json.dumps({'accept': False, 'csrf_token': csrf_token})
                response = client.post('/post-action', data=data,
                        content_type=self.content_type_json)
                self.assertEquals(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEquals(data['payload']['message'], 'tou.must-accept')
