# Copyright 2022 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import urllib.parse

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.errors import NotFoundError
from synapse.rest.client import (
    devices,
    login,
    logout,
    soft_logout,
    soft_token_invalidate,
)
from synapse.rest.client.account import WhoamiRestServlet
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config

LOGIN_URL = b"/_matrix/client/r0/login"
TEST_URL = b"/_matrix/client/r0/account/whoami"


class SoftLogoutRestTestCase(unittest.HomeserverTestCase):
    """Test for client /soft_logout and /soft_logout/all"""

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        devices.register_servlets,
        logout.register_servlets,
        lambda hs, http_server: WhoamiRestServlet(hs).register(http_server),
        soft_logout.register_servlets,
        soft_token_invalidate.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.hs = self.setup_test_homeserver()
        self.hs.config.registration.enable_registration = True
        self.hs.config.registration.registrations_require_3pid = []
        self.hs.config.registration.auto_join_rooms = []
        self.hs.config.captcha.enable_registration_captcha = False

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")
        self.url = "/_synapse/admin/v1/users/%s/login" % urllib.parse.quote(
            self.other_user
        )
        self.handler = hs.get_device_handler()

    def _get_token(self) -> str:
        channel = self.make_request(
            "POST", self.url, b"{}", access_token=self.admin_user_tok
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        return channel.json_body["access_token"]

    @override_config(
        {
            "session_lifetime": "24h",
            "experimental_features": {"msc1466_soft_logout": True},
        }
    )
    def test_soft_token_invalidate(self) -> None:
        """Test that current device gets soft-logged out
        when POSTing on `/soft_logout`."""
        # Register user
        self.register_user("kermit", "monkey")

        # Log in as normal
        access_token = self.login("kermit", "monkey")

        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEqual(channel.code, 200, channel.result)

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEqual(channel.code, 200, channel.result)

        # save device_id for relogin later
        # and user_id to verify device did not get destroyed
        device_id = channel.json_body["device_id"]
        user_id = channel.json_body["user_id"]

        # Request soft_token_validation for this_session
        channel = self.make_request(
            b"POST", "/soft_token_invalidate", access_token=access_token
        )
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Verify we are soft-logged-out
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEqual(channel.code, 401, channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEqual(channel.json_body["soft_logout"], True)

        # Verify that the pair user_id,device_id did not do a hard_logout
        self.get_success(self.handler.get_device(user_id, device_id))

        # Reconnect on the same device
        access_token = self.login("kermit", "monkey", device_id=device_id)

        # Verify we can GET without problems
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEqual(channel.code, 200, channel.result)

        # Final log-out.
        channel = self.make_request(b"POST", "/logout", access_token=access_token)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Verify that the device no longer exists for user_id
        self.get_failure(self.handler.get_device(user_id, device_id), NotFoundError)

    @override_config(
        {
            "session_lifetime": "24h",
            "experimental_features": {"msc1466_soft_logout": True},
        }
    )
    def test_soft_logout_all(self) -> None:
        """Tests that all devices get soft-logged out
        when POSTing on `/soft_logout/all`."""
        # Register user
        self.register_user("kermit", "monkey")

        # Log-in to three different devices
        device_id_1 = "LIMONADEN"
        device_id_2 = "CITRONADE"
        device_id_3 = "FORNIMAEN"

        # Log in as normal in each one of them
        access_token_1 = self.login("kermit", "monkey", device_id_1)
        access_token_2 = self.login("kermit", "monkey", device_id_2)
        access_token_3 = self.login("kermit", "monkey", device_id_3)

        # we should now be able to make requests with the access tokens
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token_1)
        self.assertEqual(channel.code, 200, channel.result)
        user_id = channel.json_body["user_id"]

        # POST soft_logout/all with first access token
        channel = self.make_request(
            b"POST", "/soft_token_invalidate/all", access_token=access_token_1
        )
        self.assertEqual(channel.code, 200, channel.result)

        # Verify that the pairs user_id,device_id did not do a hard_logout
        self.get_success(self.handler.get_device(user_id, device_id_1))
        self.get_success(self.handler.get_device(user_id, device_id_2))
        self.get_success(self.handler.get_device(user_id, device_id_3))

        # We should be soft_logged out
        # Using second token for demonstration purposes
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token_2)
        self.assertEqual(channel.code, 401, channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEqual(channel.json_body["soft_logout"], True)

        # Reconnect on the two devices, and not the third
        access_token_1 = self.login("kermit", "monkey", device_id=device_id_1)
        access_token_2 = self.login("kermit", "monkey", device_id=device_id_2)

        # Verify GET is successful
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token_1)
        self.assertEqual(channel.code, 200, channel.result)

        # Final log-out should work on all three
        channel = self.make_request(b"POST", "/logout", access_token=access_token_1)
        self.assertEqual(channel.code, 200, msg=channel.result)
        channel = self.make_request(b"POST", "/logout", access_token=access_token_2)
        self.assertEqual(channel.code, 200, msg=channel.result)
        channel = self.make_request(b"POST", "/logout", access_token=access_token_3)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Verify each (user,device) existence status
        self.get_failure(self.handler.get_device(user_id, device_id_1), NotFoundError)
        self.get_failure(self.handler.get_device(user_id, device_id_2), NotFoundError)
        self.get_failure(self.handler.get_device(user_id, device_id_3), NotFoundError)
