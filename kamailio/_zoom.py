##
##
##

from openapi3 import OpenAPI
import json
import jwt
import config
import time
import trio
import asks
from pprint import pprint
from pathlib import Path
from contextlib import asynccontextmanager

try:
    from kamailio import var
except ImportError:
    var=None

numByNr={}
numById={}
numUnseen=set()

shvPrefix = "zoom_"
auth_token_url = "https://zoom.us/oauth/token"

def updateNumber(nr):
    try:
        onr = numById.pop(nr.id)
    except KeyError:
        pass
    else:
        del numByNr[onr.number]
        del var.SHV[shvPrefix+onr.number]

    if not nr.carrier or nr.carrier.name != 'BYOC':
        return

    numByNr[nr.number]=nr
    numById[nr.id]=nr
    if var is not None:
        var.SHV[shvPrefix+nr.number] = nr.assignee is not None
    numUnseen.discard(nr.id)

async def updateNumbers(api):
    numUnseen=set(numById.keys())
    res=await api.call_listAccountPhoneNumbers(parameters=dict(type="byoc",page_size=100,next_page_token=None))
    while True:
        for r in res.phone_numbers:
            if r.assignee is None:
                continue
            updateNumber(r)
            
        npt=res.next_page_token
        if not npt:
            break
        res=await api.call_listAccountPhoneNumbers(parameters=dict(type="byoc",next_page_token=npt,page_size=100))

    for nid in numUnseen:
        onr = numById.pop(nid)
        del numByNr[onr.number]

async def refresh_numbers(api, task_status=trio.TASK_STATUS_IGNORED):
    while True:
        await updateNumbers(api)
        task_status.started()
        await trio.sleep(1200)

async def app_server(api, task_status=trio.TASK_STATUS_IGNORED):
    from quart_trio import QuartTrio
    from quart import request
    import hmac
    import hashlib
    from pprint import pprint

    app = QuartTrio("kazoom")
    @app.post("/evt")
    async def evt(*a,**k):
        msg = (await request.json)
        pprint(msg)
        try:
            msg = msg["payload"]["plainToken"]
            signature = hmac.new(bytes(config.SECRET_TOKEN, 'utf-8'), msg = bytes(msg , 'utf-8'), digestmod = hashlib.sha256).hexdigest().lower()
            return dict(
                plainToken=msg,
                encryptedToken=signature,
            )
        except KeyError:
            return {}
    await app.run_task(port=50080)

async def refresh_token(api, sess, task_status=trio.TASK_STATUS_IGNORED):
    data = {
        "grant_type": "account_credentials",
        "account_id": config.ACCT_ID,
        "client_secret": config.CLIENT_SECRET,
    }
    while True:
        response = await sess.post(auth_token_url,
             auth=asks.BasicAuth((config.CLIENT_ID, config.CLIENT_SECRET),),
             data=data)
        if response.status_code != 200:
            raise RuntimeError("Unable to get access token",response.text)
            # continue
        response_data = response.json()
        access_token = response_data["access_token"]
        if task_status is not None:
            task_status.started()
            task_status = None
        api.authenticate('Bearer', "Bearer "+access_token)
        await trio.sleep(response_data["expires_in"]*2/3)

@asynccontextmanager
async def zoom_worker():
    with (Path(__file__).parent / "_data" / "zoom" / "phone.json").open("r") as _f:
        _s = json.load(_f)

    async with OpenAPI(_s) as api, trio.open_nursery() as n:
        sess = asks.Session(connections=3)
        await n.start(refresh_token, api, sess)
        await n.start(refresh_numbers, api)
        await n.start(app_server, api)
        try:
            yield api
        finally:
            n.cancel_scope.cancel()

if __name__ == "__main__":
    with (Path(__file__).parent / "_data" / "zoom" / "phone.json").open("r") as _f:
        _s = json.load(_f)

    async def main():
        async with OpenAPI(_s) as api, trio.open_nursery() as n:
            await n.start(app_server, api)

    async def main2():
        async with OpenAPI(_s) as api, trio.open_nursery() as n:
            sess = asks.Session(connections=3)
            await n.start(refresh_token, api, sess)
            await updateNumbers(api)
            n.cancel_scope.cancel()


    trio.run(main2)
