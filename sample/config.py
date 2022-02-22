class _obj: pass
ip = _obj()
ip.pbx = ("udp","192.168.99.9")
ip.world = ("tcp","10.9.9.9")
ip.self = (None,"10.1.1.9")

VIA = {
        "90009":("+496990009","pbx"),
        "06990009":("+496990009","pbx"),
        "00496990009":("+496990009","pbx"),
    }

def nr_fix(nr):
    if nr == "0" or (len(nr) == 3 and nr not in {"112","110"}):
        return f"+496990009{nr}"
    return nr

