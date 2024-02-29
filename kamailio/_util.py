import re

_nr = re.compile(r"\$(\d)")
def match(cfg, nr):
    """
    @cfg is a dict with a 'match' regexp, an optional 'result' string and
    an optional 'dest' string.

    If @nr matches, replace with 'dest' if given and return (nr,dest) tuple.
    Otherwise return `None`.
    """
    m = cfg["match"].match(nr)
    if m is None:
        return None
    if "result" in cfg:
        def repl(p):
            return m.group(int(p[1]))
        nr = _nr.sub(repl, cfg["result"])
    else:
        nr = None

    return nr,cfg.get("dest",None)


