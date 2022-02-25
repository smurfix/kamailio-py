# everybody needs these

import threading
class _State(threading.local):
    id = 0

    def setup(self, id):
        self.id = id
thread_state = _State()

# could use dataclasses but let's not import unnecessary stuff
class Provider:
    def __init__(self,domain,transport,addr):
        self.domain = domain
        self.transport = transport
        self.addr = addr

    def __repr__(self):
        return f"Ext({self.domain!r}: {self.transport} {self.addr})"


from sys import exit
from . import log
from . import var

