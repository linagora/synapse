# Copyright 2016 OpenMarket Ltd
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

import logging
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class SoftLogoutRestServlet(RestServlet):
    """
    This is a potential implementation soft_logout by request.

    The client soft-logs out by request, thus requiring re-authentication without
    destroying the device.

    To soft-logout from current device
    Request:
    POST /soft_logout HTTP/1.1

    Response:
    HTTP/1.1 200
    Content: {}

    To soft-logout from all devices
    Request:
    POST /soft_logout/all HTTP/1.1

    Response:
    HTTP/1.1 200
    Content: {}
    """

    PATTERNS = client_patterns("/soft_logout$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        """Causes the device to soft_logout.

        Returns:
        200, {}
        """
        requester = await self.auth.get_user_by_req(request, allow_expired=True)
        user_id = requester.user.to_string()

        # AuthHandler's method deletes all the tokens and refresh tokens associated,
        # as specified in RegistrationStore. Only soft_logout current device
        await self._auth_handler.delete_access_tokens_for_user(
            user_id, device_id=requester.device_id
        )

        return 200, {}


class SoftLogoutAllRestServlet(RestServlet):
    PATTERNS = client_patterns("/soft_logout/all$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_expired=True)
        user_id = requester.user.to_string()

        # Soft_logout all devices
        await self._auth_handler.delete_access_tokens_for_user(user_id)
        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.experimental.msc1466_soft_logout:
        SoftLogoutRestServlet(hs).register(http_server)
        SoftLogoutAllRestServlet(hs).register(http_server)
