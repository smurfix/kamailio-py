
from kamailio import Provider

import re

PROVIDER = {
    "pbx": Provider("pbx.local","udp","192.168.99.9"),
    "world": Provider("world.example","tcp","10.9.9.9"),
    "special": Provider("secret.example","tls","10.3.4.5"),
}

here = re.compile("(\\+4969|004969|069|)90009")

def ROUTE(nr):
    m = loc.match(nr)
    if m:
        return "+496990009"+nr[m.end():],"pbx"

    if nr.startswith("+"):
        return nr,"world"
    if nr.startswith("00"):
        return "+"+nr[2:],"world"
    if nr.startswith("0"):
        return "+49"+nr[1:],"world"
    return "+4969"+nr,"world"

def nr_fix(nr):
    if nr == "0" or (len(nr) == 3 and nr not in {"112","110"}):
        return f"+496990009{nr}"
    return nr

