# everybody needs these
from __future__ import annotations

import threading
from sys import exit  # noqa:F401

from . import log as log  # noqa:PLC0414  # ruff bug *sigh*

try:  # noqa:SIM105
    from . import var  # noqa:F401
except ImportError:
    pass


class _State(threading.local):
    id = 0

    def setup(self, id):
        self.id = id


thread_state = _State()
