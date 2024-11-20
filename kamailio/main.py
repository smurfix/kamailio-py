"""
Main code for processing kamailio requests.
"""

from contextlib import suppress
import logging

from kamailio._basic import Kamailio
import kamailio.log as log_
from kamailio.trace import trace_enable

logger = logging.getLogger("main")

def mod_init():
    """
    Global function to instantiate a kamailio class object.
    Executed when the kamailio app_python module is initialized.

    Returns the Kamailio object.
    """
    log_.init(stderr=True)

    from ._config import Cfg
    cfg = Cfg()
    with suppress(KeyError):
        trace_enable(cfg.cfg["debug"]["trace"])
    return Kamailio(cfg, logger=logger)

def child_init(*a,**k):
    logger.debug("Child Init %r %r", a, k)
