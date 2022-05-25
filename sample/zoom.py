from openapi3 import OpenAPI
import json
import jwt
import config
import time
import trio
from pprint import pprint


numByNr={}
numById={}
numUnseen=set()


def updateNumber(nr):
    try:
        onr = numById.pop(nr.id)
    except KeyError:
        pass
    else:
        del onr

    numByNr[nr.number]=nr
    numById[nr.id]=nr
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
            return
        print("NEXT",npt)
        res=await api.call_listAccountPhoneNumbers(parameters=dict(type="byoc",next_page_token=npt,page_size=100))

    for nid in numUnseen:
        onr = numById.pop(nid)
        del numByNr[onr.number]


# authenticate using a securityScheme defined in the spec's components.securitySchemes
def generate_jwt(key, secret):
    header = {"alg": "HS256", "typ": "JWT"}

    payload = {"iss": key, "exp": int(time.time() + 3600*24*365*10), }
    #payload = {"appKey": key, "iat": int(time.time()), "exp": int(time.time() + 3600), "tokenExp":3600}

    token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
    return token.decode("ascii")

async def main():
    with open("data/zoom/phone.json","r") as _f:
        _s = json.load(_f)

    async with OpenAPI(_s) as api:
        token = generate_jwt(config.API_KEY, config.API_SECRET)
        #print(token)
        api.authenticate('Bearer', "Bearer "+token)
        #pprint(api.call_listAutoReceptionists())
        await updateNumbers(api)


#import requests
#r = requests.get("https://api.zoom.us/v2/phone/blocked_list", headers={'Authorization': 'Bearer '+token})
#print(r,r.text)

trio.run(main)
