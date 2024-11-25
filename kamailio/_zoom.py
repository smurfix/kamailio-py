##
##
##
from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from pprint import pprint

import httpx
import trio
from asyncopenapi3 import OpenAPI

logger = logging.getLogger(__name__)

try:
    from kamailio import var
except ImportError:
    var = None


class ZoomWrapper:
    shvPrefix = "zoom_"

    def __init__(self, cfg, _debug=False):
        self.cfg = cfg

        self.numByNr = {}
        self.numById = {}
        self.numUnseen = set()

        self._debug = _debug

    def updateNumber(self, nr):
        try:
            onr = self.numById.pop(nr.id)
        except KeyError:
            pass
        else:
            del self.numByNr[onr.number]
            if var is not None:
                del var.SHV[self.shvPrefix + onr.number]

        if not nr.carrier or nr.carrier.name != "BYOC":
            return

        self.numByNr[nr.number] = nr
        self.numById[nr.id] = nr
        if var is not None:
            var.SHV[self.shvPrefix + nr.number] = nr.assignee is not None
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
            await trio.sleep(1200)

    async def app_server(self, task_status=trio.TASK_STATUS_IGNORED):
        import hashlib
        import hmac

        from quart import request
        from quart_trio import QuartTrio

        token = self.cfg["zoom"]["cred"]["token"]

        app = QuartTrio("kazoom")

        @app.post("/evt")
        async def evt(*a, **k):
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

        await app.run_task(port=50080, task_status=task_status)

    async def refresh_token(self, task_status=trio.TASK_STATUS_IGNORED):
        cred = self.cfg["zoom"]["cred"]
        data = {
            "grant_type": "account_credentials",
            "account_id": cred["account"],
            "client_secret": cred["secret"],
        }
        while True:
            logger.info("Start: update auth")
            response = await self.sess.post(
                self.cfg["zoom"]["url"],
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

    __ctx = None

    async def __aenter__(self):
        self.__ctx = ctx = self._ctx()  # pylint: disable=E1101,W0201
        return await ctx.__aenter__()

    def __aexit__(self, *tb):
        try:
            return self.__ctx.__aexit__(*tb)
        finally:
            self.__ctx = None

    @asynccontextmanager
    async def _ctx(self):
        with (Path(__file__).parent / "_data" / "zoom" / "phone.json").open("r") as _f:
            _s = json.load(_f)

        async with OpenAPI(_s) as self.api, trio.open_nursery() as n:
            self.sess = httpx.AsyncClient(limits=httpx.Limits(max_connections=3))
            if not self._debug:
                await n.start(self.refresh_token)
                await n.start(self.refresh_numbers)
                await n.start(self.app_server)
            try:
                yield self
            finally:
                n.cancel_scope.cancel()


if __name__ == "__main__":
    with (Path(__file__).parent / "_data" / "zoom" / "phone.json").open("r") as _f:
        _s = json.load(_f)

    async def main(cfg):
        async with ZoomWrapper(cfg, _debug=True) as z, trio.open_nursery() as n:
            await n.start(z.app_server)

    async def main2(cfg):
        async with ZoomWrapper(cfg, _debug=True) as z, trio.open_nursery() as n:
            await n.start(z.refresh_token)
            await z.updateNumbers()
            n.cancel_scope.cancel()

    logging.basicConfig(level=logging.DEBUG)

    from kamailio._config import Cfg

    cfg = Cfg(sys.argv[1], sys.argv[2])
    trio.run(main2, cfg)
