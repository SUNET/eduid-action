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

__author__ = 'ft'

import datetime
from eduid_userdb.credentials import U2F, Webauthn

from . import RESULT_CREDENTIAL_KEY_NAME


def add_actions(idp_app, user, ticket):
    """
    Add an action requiring the user to login using one or more additional
    authentication factors.

    This function is called by the IdP when it iterates over all the registered
    action plugins entry points.

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: the SSO login data

    :type idp_app: eduid_idp.idp.IdPApplication
    :type user: eduid_idp.idp_user.IdPUser
    :type ticket: eduid_idp.loginstate.SSOLoginData

    :return: None
    """
    u2f_tokens = user.credentials.filter(U2F).to_list()
    webauthn_tokens = user.credentials.filter(Webauthn).to_list()
    tokens = u2f_tokens + webauthn_tokens
    if not tokens:
        idp_app.logger.debug('User does not have any U2F or Webauthn tokens registered')
        return None

    if not idp_app.actions_db:
        idp_app.logger.warning('No actions_db - aborting MFA action')
        return None

    existing_actions = idp_app.actions_db.get_actions(user.eppn, ticket.key,
                                                      action_type = 'mfa',
                                                      )
    if existing_actions and len(existing_actions) > 0:
        idp_app.logger.debug('User has existing MFA actions - checking them')
        if check_authn_result(idp_app, user, ticket, existing_actions):
            for this in ticket.mfa_action_creds:
                idp_app.authn.log_authn(user, success=[this.key], failure=[])
            return
        idp_app.logger.error('User returned without MFA credentials')

    idp_app.logger.debug('User must authenticate with a token (has {} token(s))'.format(len(tokens)))
    idp_app.actions_db.add_action(
        user.eppn,
        action_type = 'mfa',
        preference = 1,
        session = ticket.key,  # XXX double-check that ticket.key is not sensitive to disclose to the user
        params = {})


def check_authn_result(idp_app, user, ticket, actions):
    """
    The user returned to the IdP after being sent to actions. Check if actions has
    added the results of authentication to the action in the database.

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: the SSO login data
    :param actions: Actions in the ActionDB matching this user and session

    :type idp_app: eduid_idp.idp.IdPApplication
    :type user: eduid_idp.idp_user.IdPUser
    :type ticket: eduid_idp.loginstate.SSOLoginData
    :type actions: list of eduid_userdb.actions.Action

    :return: MFA action with proof of completion found
    :rtype: bool
    """
    for this in actions:
        idp_app.logger.debug('Action {} authn result: {}'.format(this, this.result))
        if this.result.get('success') is True:
            key = this.result.get(RESULT_CREDENTIAL_KEY_NAME)
            cred = user.credentials.find(key)
            if cred:
                utc_now = datetime.datetime.utcnow().replace(tzinfo = None)  # thanks for not having timezone.utc, Python2
                ticket.mfa_action_creds[cred] = utc_now
                idp_app.logger.debug('Removing MFA action completed with {}'.format(cred))
                idp_app.actions_db.remove_action_by_id(this.action_id)
                return True
            else:
                idp_app.logger.error('MFA action completed with unknown key {}'.format(key))
    return False
