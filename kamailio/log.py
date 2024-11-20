# Logging handler that hooks into Kamailio
from __future__ import annotations

import logging
import sys

try:
    import KSR
except ImportError:
    KSR = None

#   CRITICAL = 50
#   DEBUG = 10
#   ERROR = 40
#   FATAL = 50
#   INFO = 20
#   NOTSET = 0
#   WARN = 30
#   WARNING = 30

_levels = {
    -5: logging.CRITICAL + 10,  # L_ALERT
    -4: logging.CRITICAL + 5,  # L_BUG
    -3: logging.CRITICAL,
    -1: logging.ERROR,
    0: logging.WARNING,
    1: logging.INFO + 5,  # L_ERR
    2: logging.INFO,
    3: logging.DEBUG,
}
_rlevels = {v: k for k, v in _levels.items()}


def _lvl2txt(i):
    if i <= logging.DEBUG:
        return "dbg"
    if i <= logging.INFO:
        return "info"
    if i <= logging.INFO + 5:
        return "notice"
    if i <= logging.WARNING:
        return "warn"
    if i <= logging.ERROR:
        return "err"
    return "crit"


logger = logging.getLogger("L")


def _level(n):
    return _levels.get(n, logging.ERROR)


class KSRHandler(logging.Handler):
    def emit(self, record):
        if hasattr(KSR, "log_systemd"):
            lvl = _rlevels[record.levelno]
            KSR.log_systemd.sd_journal_print(f"LOG_{logging.getLevelName(lvl)}", self.getMessage())
        else:
            lvl = _lvl2txt(record.levelno)
            KSR.log(lvl, record.getMessage())


def init(stderr=False):
    global _stdin, _stdout  # noqa:PLW0602
    try:
        sys.stdin = open("/dev/tty")  # noqa:SIM115
        sys.stdout = open("/dev/tty", "w")  # noqa:SIM115
    except OSError:
        pass

    cfg = {}
    if KSR is not None:
        cfg["handlers"] = [KSRHandler()]

    logging.basicConfig(level=logging.DEBUG, **cfg)
    if stderr:
        logging.root.addHandler(logging.StreamHandler(sys.stderr))


def dump_obj(obj, n="?"):
    for attr in dir(obj):
        if attr.startswith("__"):
            continue
        try:
            if attr in {"f_builtins", "f_globals"}:
                val = "{**}"
            else:
                try:
                    val = getattr(obj, attr)
                except RuntimeError:
                    continue  # msg.status when not a numeric message
        except SystemError:
            logger.debug(f"{n}.{attr} = ?")
        else:
            #           if callable(val):
            #               val = "…fn()"
            try:
                val = str(val)
            except Exception as exc:
                val = f"? {val.__class__.__name__} {exc}"
            logger.debug(f"{n}.{attr} = {val}")
