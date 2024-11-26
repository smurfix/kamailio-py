##
##
##
from __future__ import annotations

import json
import logging
import sys
import math
from contextlib import asynccontextmanager
from pathlib import Path
from pprint import pprint

from quart import request
import httpx
import trio
from asyncopenapi3 import OpenAPI

from ._provider import Provider as _Provider

logger = logging.getLogger(__name__)

try:
    from kamailio import var
except ImportError:
    var = None


class ZoomProvider(_Provider):

    def __init__(self, auth_url=None, cred=None, update=0, known=(), **kw):
        super().__init__(**kw)

        self.numByNr = {}
        self.numById = {}
        self.numUnseen = set()
        self._known = known
        self._shvPrefix = f"_{self.name}_"
        self._update=update

        self._auth_url = auth_url
        self._cred = cred

    def updateNumber(self, nr):
        try:
            onr = self.numById.pop(nr.id)
        except KeyError:
            pass
        else:
            del self.numByNr[onr.number]
            if var is not None:
                del var.SHV[self._shvPrefix + onr.number]

        if not nr.carrier or nr.carrier.name != "BYOC":
            return

        self.numByNr[nr.number] = nr
        self.numById[nr.id] = nr
        if var is not None:
            var.SHV[self._shvPrefix + nr.number] = nr.assignee is not None
        self.numUnseen.discard(nr.id)

    async def updateNumbers(self):
        self.numUnseen = set(self.numById.keys())
        logger.info("Start: update numbers")
        n = x = 0
        try:
            res = await self.api.call_listAccountPhoneNumbers(
                parameters=dict(type="byoc", page_size=100, next_page_token=None)
            )
            while True:
                for r in res.phone_numbers:
                    if r.assignee is None:
                        x += 1
                        continue
                    n += 1
                    self.updateNumber(r)

                npt = res.next_page_token
                if not npt:
                    break
                res = await self.api.call_listAccountPhoneNumbers(
                    parameters=dict(type="byoc", next_page_token=npt, page_size=100)
                )
        except Exception:
            logger.exception("Update numbers")
            return

        for nid in self.numUnseen:
            onr = self.numById.pop(nid)
            del self.numByNr[onr.number]
        logger.info("Done: update numbers (%d assigned, %d free)", n, x)

    async def refresh_numbers(self, task_status=trio.TASK_STATUS_IGNORED):
        while True:
            await self.updateNumbers()
            if task_status is not None:
                task_status.started()
                task_status = None
            if self._update < 0:
                return
            await trio.sleep(self._update)


    async def refresh_token(self, task_status=trio.TASK_STATUS_IGNORED):
        cred = self._cred
        data = {
            "grant_type": "account_credentials",
            "account_id": cred["account"],
            "client_secret": cred["secret"],
        }
        while True:
            logger.info("Start: update auth")
            response = await self.sess.post(
                self._auth_url,
                auth = httpx.BasicAuth(username=cred["client"], password=cred["secret"]),
                data=data,
            )
            if response.status_code != 200:
                raise RuntimeError("Unable to get access token", response.text)
                # continue
            response_data = response.json()
            access_token = response_data["access_token"]
            self.api.authenticate("Bearer", "Bearer " + access_token)

            logger.info("Start: auth done")
            if task_status is not None:
                task_status.started()
                task_status = None
            await trio.sleep(response_data["expires_in"] * 2 / 3)


    async def _evt(self, *a, **k):
        a, k  # noqa:B018
        msg = await request.json
        pprint(msg)
        try:
            msg = msg["payload"]["plainToken"]
            signature = (
                hmac.new(
                    bytes(token, "utf-8"), msg=bytes(msg, "utf-8"), digestmod=hashlib.sha256
                )
                .hexdigest()
                .lower()
            )
            return dict(
                plainToken=msg,
                encryptedToken=signature,
            )
        except KeyError:
            return {}

    async def match_known(self, nr):
        try:
            return var.SHV[self._shvPrefix + nr]
        except KeyError:
            return False

    async def run(self, kam):
        if var is not None:
            for nr in self._known:
                var.SHV[self._shvPrefix + nr] = True
        with (Path(__file__).parent / "_data" / "zoom" / "phone.json").open("r") as _f:
            _s = json.load(_f)
        async with (
                OpenAPI(_s) as self.api,
                trio.open_nursery() as n,
                ):
            self.sess = httpx.AsyncClient(limits=httpx.Limits(max_connections=3))
            await n.start(self.refresh_token)
            if self._update:
                await n.start(self.refresh_numbers)
            logger.debug("Zoom subsystem is up.")
            if kam.app is not None:
                kam.app.add_url_rule("/zoom/evt", methods=["POST"], view_func=self._evt)

            await trio.sleep(math.inf)
