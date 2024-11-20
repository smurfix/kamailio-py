from __future__ import annotations

from kamailio._config import Cfg

_tests = [
    "anonymous:12345:pa 0098765:1212345:pb",
    "733445:+245678:pb +733445:+245678:pa",
    "727272:+235678:pb +727272:+345678:pa",
    "545454:55555:pa 49911545454:0067555589:pc",
    "032198765:65554:pa 4932198765:0065554:pc",
    "+545454:00123987:pc 00545454:12123987:pb",
]


def test_basic():
    c = Cfg("tests/test_cfg.yaml")

    for sd in _tests:
        s, d = sd.split(" ")
        sa, sb, sp = s.split(":")
        da, db, dp = d.split(":")
        sp = c.provider[sp]
        dp = None if dp == "-" else c.provider[dp]

        ia = sp.format_a_in(sa)  # noqa:F841
        r = c.route(sb, sp)
        sa = sp.format_a_in(sa)
        if r is None:
            ra = sa
            rb = sb
            rp = None
        else:
            rb, rp = r
            ra = sa
            if rp:
                ra = rp.format_a_out(ra)

        assert (da, db, dp) == (ra, rb, rp), f"{sd} {ra}:{rb}:{rp._name if rp else '-'}"  # noqa:SLF001
