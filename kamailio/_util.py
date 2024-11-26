from __future__ import annotations

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

    return nr, cfg.get("dest", None)


# We need the task status

import trio
from quart_trio.app import QuartTrio as _QuartTrio
from hypercorn.trio import serve
from hypercorn.config import Config as HyperConfig

class QuartTrio(_QuartTrio):
    def run_task(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        debug: Optional[bool] = None,
        ca_certs: Optional[str] = None,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        shutdown_trigger: Optional[Callable[..., Awaitable[None]]] = None,
        task_status: trio.TaskStatus = trio.TASK_STATUS_IGNORED,
    ) -> Coroutine[None, None, None]:
        """Return a task that when awaited runs this application.

        This is best used for development only, see Hypercorn for
        production servers.

        Arguments:
            host: Hostname to listen on. By default this is loopback
                only, use 0.0.0.0 to have the server listen externally.
            port: Port number to listen on.
            debug: If set enable (or disable) debug mode and debug output.
            ca_certs: Path to the SSL CA certificate file.
            certfile: Path to the SSL certificate file.
            keyfile: Path to the SSL key file.

        """
        config = HyperConfig()
        config.access_log_format = "%(h)s %(r)s %(s)s %(b)s %(D)s"
        config.accesslog = "-"
        config.bind = [f"{host}:{port}"]
        config.ca_certs = ca_certs
        config.certfile = certfile
        if debug is not None:
            config.debug = debug
        config.errorlog = config.accesslog
        config.keyfile = keyfile

        return serve(self, config, shutdown_trigger=shutdown_trigger,
                     task_status=task_status)

