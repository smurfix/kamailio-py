from openapi3 import OpenAPI
import json
import jwt
import config

with open("data/zoom/phone.json","r") as _f:
    _s = json.load(_f)

api = OpenAPI(_s)

del _f
del _s

regions = api.call_getRegions()

# authenticate using a securityScheme defined in the spec's components.securitySchemes
def generate_jwt(key, secret):
    header = {"alg": "HS256", "typ": "JWT"}

    payload = {"iss": key, "exp": int(time.time() + 3600)}

    token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
    return token.decode("utf-8")

token = generate_jwt(config.API_KEY, config.API_SECRET)
api.authenticate('Bearer', token)

breakpoint()
pass

