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

from kamailio import var

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
    var.SHV[shvPrefix+onr.number] = nr.assignee is not None
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

async def main(setup_done=lambda: None):
    with open("/root/kamailio-py/data/zoom/phone.json","r") as _f:
        _s = json.load(_f)

    async with OpenAPI(_s) as api, trio.open_nursery() as n:
        await n.start(refresh_auth, api)
        await n.start(refresh_numbers, api)
        setup_done()

if __name__ == "__main__":
    trio.run(main)
