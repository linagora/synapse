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


class InvalidateTokenRestServlet(RestServlet):
    """
    This was meant to allow soft_logout for users
    The current implementation forcefully relies on tokens becoming invalid
    when validity time expires.
    This method would allow users to cause the validity time of the token
    used to set to 0, thus indirectly causing a soft_logout.

    To invalidate current token
    Request:
    POST /soft_token_invalidate HTTP/1.1

    Response:
    HTTP/1.1 200
    Content: {}

    To invalidate all the user's access tokens
    Request:
    POST /soft_token_invalidate/all HTTP/1.1

    Response:
    HTTP/1.1 200
    Content: {}
    """

    PATTERNS = client_patterns("/soft_token_invalidate$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self._auth_handler = hs.get_auth_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        """Causes the token validity time to set to current clock time.

        Returns:
        200, {}
        """
        requester = await self.auth.get_user_by_req(request, allow_expired=True)
        assert requester.access_token_id is not None
        access_id: int = requester.access_token_id
        access_token = self.auth.get_access_token_from_request(request)

        # Invalidate current access token only
        await self.store.set_access_token_validity(
            access_token, access_id, self.clock.time_msec()
        )

        return 200, {}


class InvalidateTokenAllRestServlet(RestServlet):
    PATTERNS = client_patterns("/soft_token_invalidate/all$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self._auth_handler = hs.get_auth_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_expired=True)
        user_id = requester.user.to_string()

        # soft_token_invalidate all devices
        await self.store.user_set_account_tokens_validity(
            user_id,
            validity_until_ms=self.clock.time_msec(),
            except_token_id=None,
            device_id=None,
        )
        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.experimental.msc1466_soft_logout:
        InvalidateTokenRestServlet(hs).register(http_server)
        InvalidateTokenAllRestServlet(hs).register(http_server)
