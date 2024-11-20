"""
Zoom integration
"""

from __future__ import annotations

import math

import trio


async def init(kam):
    kam  ## noqa:B018
    from ._zoom import zoom_worker

    async with zoom_worker():
        await trio.sleep(math.inf)
