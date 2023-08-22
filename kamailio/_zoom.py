##
##
##

from openapi3 import OpenAPI
import json
import jwt
import config
import time
import trio
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
    res=await api.call_listAccountPhoneNumbers(parameters=dict(type="byoc",page_size=100))
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

# authenticate using a securityScheme defined in the spec's components.securitySchemes
def generate_jwt(key, secret):
    header = {"alg": "HS256", "typ": "JWT"}

    payload = {"iss": key, "exp": int(time.time() + 3600), }

    token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
    return token.decode("ascii")

async def refresh_auth(api, task_status=trio.TASK_STATUS_IGNORED):
    while True:
        token = generate_jwt(config.API_KEY, config.API_SECRET)
        api.authenticate('Bearer', "Bearer "+token)

        task_status.started()
        await trio.sleep(1700)


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


@asynccontextmanager
async def zoom_worker():
    with (Path(__file__).parent / "_data" / "zoom" / "phone.json").open("r") as _f:
        _s = json.load(_f)

    async with OpenAPI(_s) as api, trio.open_nursery() as n:
        await n.start(refresh_auth, api)
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


    trio.run(main)
