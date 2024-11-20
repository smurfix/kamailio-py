"""
Zoom integration
"""

from __future__ import annotations

import math

import trio

import logging
logger = logging.getLogger(__name__)

async def init(kam):
    from ._zoom import ZoomWrapper

    async with (
            ZoomWrapper(kam.cfg, _debug=True) as z,
            trio.open_nursery() as n,
            ):
        await n.start(z.refresh_token)
        await n.start(z.refresh_numbers)
        await n.start(z.app_server)
        logger.debug("Zoom subsystem is up.")
        await trio.sleep(math.inf)
