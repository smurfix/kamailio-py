from openapi3 import OpenAPI
import json
import jwt
import config
import time
import trio
from pprint import pprint

with open("data/zoom/phone.json","r") as _f:
    _s = json.load(_f)

api = OpenAPI(_s)

del _f
del _s

# authenticate using a securityScheme defined in the spec's components.securitySchemes
def generate_jwt(key, secret):
    header = {"alg": "HS256", "typ": "JWT"}

    payload = {"iss": key, "exp": int(time.time() + 3600*24*365*10), }
    #payload = {"appKey": key, "iat": int(time.time()), "exp": int(time.time() + 3600), "tokenExp":3600}

    token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
    return token.decode("ascii")

async def main():
    token = generate_jwt(config.API_KEY, config.API_SECRET)
    print(token)
    api.authenticate('Bearer', "Bearer "+token)
#pprint(api.call_listAutoReceptionists())
    res=await api.call_listAccountPhoneNumbers()
    pprint(res)
    breakpoint()

#import requests
#r = requests.get("https://api.zoom.us/v2/phone/blocked_list", headers={'Authorization': 'Bearer '+token})
#print(r,r.text)

trio.run(main)

