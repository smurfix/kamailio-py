"""
Zoom integration
"""

import trio
import math

async def init(kam):
    from ._zoom import zoom_worker
    async with zoom_worker():
        await trio.sleep(math.inf)
