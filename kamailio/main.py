"""
Main code for processing kamailio requests.
"""

import logging

from ._basic import Kamailio
import .log as log_

logger = logging.getLogger("main")

def mod_init():
    """
    Global function to instantiate a kamailio class object.
    Executed when the kamailio app_python module is initialized.

    Returns the Kamailio object.
    """
    log_.init(stderr=True)
    trace_enable(DEF.WITH_PYTRACE)

    from ._config import Cfg
    cfg = Cfg()
    return Kamailio(cfg, logger=logger)

def child_init(*a,**k):
    logger.debug("Child Init %r %r", a, k)
