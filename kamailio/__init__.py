# everybody needs these
from __future__ import annotations

import threading
import logging
import logging.config

from sys import exit  # noqa:F401

from . import log as log  # noqa:PLC0414  # ruff bug *sigh*

try:  # noqa:SIM105
    from . import var  # noqa:F401
except ImportError:
    pass

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(module)s P%(process)d T%(thread)d %(message)s'
            },
        },
    'handlers': {
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'facility': "local0",
            'formatter': 'verbose',
            },
        },
    'root': {
        'handlers': ['syslog'],
        'level': logging.DEBUG,
        'propagate': True,
        },
    }

logging.config.dictConfig(LOGGING)


class _State(threading.local):
    id = 0

    def setup(self, id):
        self.id = id


thread_state = _State()
