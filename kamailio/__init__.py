# everybody needs these

import threading
class _State(threading.local):
    id = 0

    def setup(self, id):
        self.id = id
thread_state = _State()

from sys import exit
from . import log
from . import var

