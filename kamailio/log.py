# Logging handler that hooks into Kamailio

import functools
import logging
import os
import sys
import threading
import linecache

import KSR

from . import var

#   CRITICAL = 50
#   DEBUG = 10
#   ERROR = 40
#   FATAL = 50
#   INFO = 20
#   NOTSET = 0
#   WARN = 30
#   WARNING = 30

_levels = {
    -5: logging.CRITICAL+10, # L_ALERT
    -4: logging.CRITICAL+5, # L_BUG
    -3: logging.CRITICAL,
    -1: logging.ERROR,
    0: logging.WARNING,
    1: logging.INFO+5, # L_ERR
    2: logging.INFO,
    3: logging.DEBUG,
}
_rlevels = {v:k for k,v in _levels.items()}
def _lvl2txt(i):
    if i <= logging.DEBUG: return "dbg"
    if i <= logging.INFO: return "info"
    if i <= logging.INFO+5: return "notice"
    if i <= logging.WARNING: return "warn"
    if i <= logging.ERROR: return "err"
    return "crit"

def _level(n):
    return _levels.get(n, logging.ERROR)

class KSRHandler(logging.Handler):
    def emit(self, record):
        if hasattr(KSR,"log_systemd"):
            lvl = _rlevels[record.levelno]
            KSR.log_systemd.sd_journal_print(f"LOG_{logging.getLevelName(lvl)}", self.getMessage())
        else:
            lvl = _lvl2txt(record.levelno)
            KSR.log(lvl, record.getMessage())

def init(stderr=False):
    global _stdin,_stdout
    sys.stdin = open("/dev/tty","r")
    sys.stdout = open("/dev/tty","w")

    logging.basicConfig(handlers=[KSRHandler()], level=logging.DEBUG)
    if stderr:
        logging.root.addHandler(logging.StreamHandler(sys.stderr))

# Source: https://stackoverflow.com/questions/8315389/how-do-i-print-functions-as-they-are-called
# heavily adapted and class-ified

tracelog = logging.getLogger("T")

class _LogState(threading.local):
    level = 0
    limit = 99
    pid = 0

    def log_frame(self, frame, add="", indent=0):
        func_name = self.fname(frame)
        indent = " " * (self.level+indent+1)
        tid = self.pid
        #txt = f'{tid :3d}{indent+func_name: <35}  {frame.f_code.co_filename}, {frame.f_lineno} {add}'
        txt = f'{tid :3d} {frame.f_lineno :4d} {indent+func_name: <30} {add.strip()}'
        tracelog.debug(txt)


    @staticmethod
    def fpos(frame):
        fn = frame.f_code.co_filename
        fb = os.path.basename(fn)
        if fb == "__init__.py":
            fb = os.path.basename(os.path.dirname(fn))
        elif fb.endswith(".py"):
            fb = fb[:-3]
        return f"{fb}:{frame.f_lineno}"

    @staticmethod
    def fname(frame):
        if 'self' in frame.f_locals:
            class_name = frame.f_locals['self'].__class__.__name__
            return f"{class_name}.{frame.f_code.co_name}"
        else:
            return frame.f_code.co_name

    def tdebug(self, frame, txt, atxt="", plus=0):
        if self.limit < 0:
            return
        if frame is None:
            fn = "??"
        else:
            fn = self.fpos(frame)
        if atxt:
            atxt = f" :: {atxt}"
        tracelog.debug("%s %2d %2d  %s%s", txt,self.level+plus,self.limit,fn,atxt)

    def enter(self, frame, back=True):
        """
        Handle entering a frame.
        Return True if the rest should be skipped.
        """
        txt = ""
        oframe = None
        self.level += 1

        if self.level >= self.limit:
            # self.tdebug(frame, "LVL", txt, plus=-1)
            return True
        
        if frame and back:
            txt = self.fname(frame)
            oframe,frame = frame,frame.f_back

        # if level=0 we're in the trace start code
        # compare against 1 as we already incremented it
        if self.level > 1 and self.skip_log(frame,oframe):
            self.limit = self.level-1
            # self.tdebug(frame, "LIM", txt, plus=-1)
            return True

        # self.tdebug(frame, ">  ", txt, plus=-1)
        return False

    def exit(self, frame, back=True):
        txt=""
        if frame and back:
            txt=self.fname(frame)
            frame = frame.f_back

        self.level -= 1
        if self.level >= self.limit:
            #if not back:
            #    self.tdebug(frame, "RET",txt)
            return True
        if self.limit:
            #if not back:
            #    self.tdebug(frame, "RLI",txt)
            self.limit = 99
            return back

        #if not back:
        #    self.tdebug(frame.f_back if back else frame, "<  ", txt)
        return False

    @property
    def limited(self):
        return self.level > self.limit

    def tracer(self, prof, frame, event, arg):

        if event == "call":
            if prof:
                return
            if self.enter(frame, back=True):
                return

            self.log_frame(frame.f_back,f"> {self.fname(frame)}",-1)

        elif event == "c_call":
            if self.enter(frame, back=False):
                return

            self.log_frame(frame,f">> {arg.__name__}",-1)

        elif event == "line":
            if self.limited:
                return
            self.log_frame(frame, add=linecache.getline(frame.f_code.co_filename, frame.f_lineno))

        elif event == "return":
            if prof:
                return
            if self.exit(frame, back=True):
                return

            self.log_frame(frame.f_back,f"< {arg !r}",-1)

        elif event == "c_return":
            if self.exit(frame, back=False):
                return

            # XXX enable this when Python can return the value
            # self.log_frame(frame,f"<< {arg.__name__}",-1)

        elif event == "exception":
            if prof:
                return
            if self.limited:
                return

            self.log_frame(frame,f"E {arg[1] !r}",-1)

        elif event == "c_exception":
            if self.exit(frame, back=False):
                return
            # self.log_frame(frame,f"E {arg[1] !r}",-1)
            # XXX Python doesn't report the exception
            # https://github.com/python/cpython/pull/31393

        else:
            tracelog.debug("?Evt %s", event)


    def _ttracer(self,frame, event, arg):
        return self._tracer(False, frame, event, arg)
    def _ptracer(self,frame, event, arg):
        return self._tracer(True, frame, event, arg)

    def _tracer(self,prof, frame, event, arg):
        # print(prof, event, file=sys.stderr)
        try:
            self.tracer(prof, frame, event, arg)
        except Exception as e:
            sys.settrace(None)
            tracelog.debug("OwE", exc_info=e)
        return self._ptracer if prof else self._ttracer

    def skip_log(self, frame, oframe=None):
        if frame is None:
            return True
        if oframe is not None and oframe.f_code.co_name[0]=="<":
            return True
        if "/kamailio/log." in frame.f_code.co_filename:
            return True
        if "/kamailio/" in frame.f_code.co_filename:
            return False
        return True

    def trace(self, proc):
        """
        A wrapper that traces a function
        """
        @functools.wraps(proc)
        def pac(*a,**k):
            tf = sys.gettrace()
            pf = sys.getprofile()
            level,limit = self.level,self.limit
            self.limit = -99
            # tracelog.debug("START %s %s %r", level,limit, proc)
            sys.settrace(self._ttracer)
            sys.setprofile(self._ptracer)
            self.level,self.limit = level,limit

            try:
                return proc(*a,**k)
            finally:
                self.limit = -99
                # tracelog.debug("END   %s %s %r", level,limit, proc)
                sys.settrace(tf)
                sys.setprofile(pf)
                self.level,self.limit = level,limit
        return pac

_state = _LogState()
trace = _state.trace

def set_id(id):
    _state.pid = id


def dump_obj(obj,n="?"):
    for attr in dir(obj):
        if attr.startswith("__"):
            continue
        try:
            if attr in {"f_builtins", "f_globals"}:
                val = "{**}"
            else:
                val = getattr(obj, attr)
        except SystemError:
            tracelog.debug(f"{n}.{attr} = ?");
        else:
#           if callable(val):
#               val = "…fn()"
            try:
                val = str(val)
            except Exception as exc:
                val = f"? {val.__class__.__name__} {exc}"
            tracelog.debug(f"{n}.{attr} = {val}")
