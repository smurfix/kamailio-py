# Logging handler that hooks into Kamailio

import functools
import logging
import os
import sys
import linecache

import KSR

from . import thread_state

__export__ = [
    "trace",
    "trace_enable",
]

tracelog = logging.getLogger("T")

# set default values
type(thread_state).log_level = 0
type(thread_state).log_limit = 99

def log_frame(frame, add="", indent=0):
    func_name = fname(frame)
    indent = " " * (thread_state.log_level+indent+1)
    #txt = f'{tid :3d}{indent+func_name: <35}  {frame.f_code.co_filename}, {frame.f_lineno} {add}'
    txt = f'{thread_state.id :3d} {frame.f_lineno :4d} {indent+func_name: <30} {add.strip()}'
    tracelog.debug(txt)


def fpos(frame):
    fn = frame.f_code.co_filename
    fb = os.path.basename(fn)
    if fb == "__init__.py":
        fb = os.path.basename(os.path.dirname(fn))
    elif fb.endswith(".py"):
        fb = fb[:-3]
    return f"{fb}:{frame.f_lineno}"

def fname(frame):
    if 'self' in frame.f_locals:
        class_name = frame.f_locals['self'].__class__.__name__
        return f"{class_name}.{frame.f_code.co_name}"
    else:
        return frame.f_code.co_name

def tdebug(frame, txt, atxt="", plus=0):
    if thread_state.log_limit < 0:
        return
    if frame is None:
        fn = "??"
    else:
        fn = fpos(frame)
    if atxt:
        atxt = f" :: {atxt}"
    tracelog.debug("%s %2d %2d  %s%s", txt,thread_state.log_level+plus,thread_state.log_limit,fn,atxt)

def enter(frame, back=True):
    """
    Handle entering a frame.
    Return True if the rest should be skipped.
    """
    txt = ""
    oframe = None
    thread_state.log_level += 1

    if limited(1):
        # tdebug(frame, "LVL", txt, plus=-1)
        return True
    
    if frame and back:
        txt = fname(frame)
        oframe,frame = frame,frame.f_back

    # if level=0 we're in the trace start code
    # compare against 1 as we already incremented it
    if thread_state.log_level > 1 and skip_log(frame,oframe):
        thread_state.log_limit = thread_state.log_level-1
        # tdebug(frame, "LIM", txt, plus=-1)
        return True

    # tdebug(frame, ">  ", txt, plus=-1)
    return False

def exit(frame, back=True):
    txt=""
    if frame and back:
        txt=fname(frame)
        frame = frame.f_back

    thread_state.log_level -= 1
    if limited(0):
        #if not back:
        #    tdebug(frame, "RET",txt)
        return True
    if thread_state.log_limit:
        #if not back:
        #    tdebug(frame, "RLI",txt)
        thread_state.log_limit = 99
        return back

    #if not back:
    #    tdebug(frame.f_back if back else frame, "<  ", txt)
    return False

def limited(delta=0):
    return thread_state.log_level >= thread_state.log_limit-delta

def tracer(prof, frame, event, arg):

    if event == "call":
        if prof:
            return
        if enter(frame, back=True):
            return

        log_frame(frame.f_back,f"> {fname(frame)}",-1)

    elif event == "c_call":
        if enter(frame, back=False):
            return

        log_frame(frame,f">> {arg.__name__}",-1)

    elif event == "line":
        if limited():
            return
        log_frame(frame, add=linecache.getline(frame.f_code.co_filename, frame.f_lineno))

    elif event == "return":
        if prof:
            return
        if exit(frame, back=True):
            return

        log_frame(frame.f_back,f"< {arg !r}",-1)

    elif event == "c_return":
        if exit(frame, back=False):
            return

        # XXX enable this when Python can return the value
        # log_frame(frame,f"<< {arg.__name__}",-1)

    elif event == "exception":
        if prof:
            return
        if limited():
            return

        log_frame(frame,f"E {arg[1] !r}",-1)

    elif event == "c_exception":
        if exit(frame, back=False):
            return
        # log_frame(frame,f"E {arg[1] !r}",-1)
        # XXX Python doesn't report the exception
        # https://github.com/python/cpython/pull/31393

    else:
        tracelog.debug("?Evt %s", event)


def _ttracer(frame, event, arg):
    return _tracer(False, frame, event, arg)
def _ptracer(frame, event, arg):
    return _tracer(True, frame, event, arg)

def _tracer(prof, frame, event, arg):
    # print(prof, event, file=sys.stderr)
    try:
        tracer(prof, frame, event, arg)
    except Exception as e:
        sys.settrace(None)
        tracelog.debug("OwE", exc_info=e)
    return _ptracer if prof else _ttracer

def skip_log(frame, oframe=None):
    if frame is None:
        return True
    if oframe is not None and oframe.f_code.co_name[0]=="<":
        return True
    if "/kamailio/log." in frame.f_code.co_filename:
        return True
    if "/kamailio/" in frame.f_code.co_filename:
        return False
    return True

_do_trace = False

def trace(proc):
    """
    A wrapper that traces a function
    """
    @functools.wraps(proc)
    def pac(*a,**k):
        if not _do_trace:
            return proc(*a,**k)

        tf = sys.gettrace()
        pf = sys.getprofile()
        level,limit = thread_state.log_level,thread_state.log_limit
        thread_state.log_limit = -99
        # tracelog.debug("START %s %s %r", level,limit, proc)
        sys.settrace(_ttracer)
        sys.setprofile(_ptracer)
        thread_state.log_level,thread_state.log_limit = level,limit

        try:
            return proc(*a,**k)
        finally:
            thread_state.log_limit = -99
            # tracelog.debug("END   %s %s %r", level,limit, proc)
            sys.settrace(tf)
            sys.setprofile(pf)
            thread_state.log_level,thread_state.log_limit = level,limit
    return pac

def trace_enable(flag):
    global _do_trace
    _do_trace = flag
