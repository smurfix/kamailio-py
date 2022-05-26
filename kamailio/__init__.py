# everybody needs these

import threading

try:
    from .var import SHV as _SHV
except ImportError:
    _SHV = {}

class _State(threading.local):
    id = 0

    def setup(self, id):
        self.id = id
thread_state = _State()

# could use dataclasses but let's not import unnecessary stuff
class Provider:
    """
    Settings for providers.

    Port=0: don't try to connect.
    """
    use_port = False

    def __init__(self,domain,transport,addr, flags=0, port=None, encrypt=False, encrypt_options=""):
        if port is None:
            if transport == "tls":
                port = 5061
            else:
                port = 5060
        elif port == 0:
            self.use_port = True

        self.domain = domain
        self.transport = transport
        self.addr = addr
        self.last_addr = addr[0] if isinstance(addr,(tuple,list)) else addr
        self.flags = flags
        self.port = port
        self.encrypt = encrypt
        self.encrypt_options = encrypt_options

    @property
    def name(self):
        return self.domain.replace(".","_")

    @property
    def port(self):
        return _SHV[f"prov__{self.name}__port"]
    @port.setter
    def port(self, val):
        _SHV[f"prov__{self.name}__port"] = val

    @property
    def last_addr(self):
        return _SHV[f"prov__{self.name}__addr"]
    @last_addr.setter
    def last_addr(self, val):
        _SHV[f"prov__{self.name}__addr"] = val

    def __repr__(self):
        return f"Ext({self.domain!r}: {self.transport} {self.addr})"


from sys import exit
from . import log
try:
    from . import var
except ImportError:
    pass

