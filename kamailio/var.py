"""
This module exports a number of classes that allow you to access
Kamalio data structures (or what passes for them) in a more 

"""

import os

from threading import Lock
import logging

import KSR

logger = logging.getLogger("V")

class DNSError(RuntimeError):
    def __init__(self, name):
        self.name = name
    def __str__(self):
        return f"DNS Error: f{self.name}"

class _get:
    """
    A mix-in to provide `__*item__` methods that call `__*attr__`.
    """
    def __getitem__(self,k):
        return self.__getattr__(k)
    def __setitem__(self,k,v):
        return self.__setattr__(k,v)
    def __delitem__(self,k):
        return self.__delattr__(k)

class PV(_get):
    """
    Accessor class for named pseudovariables.

    The Kamailio pseudovariable `$name` can be accessed via `PV[name]` as well as `PV.name`.
    

    This is a singleton.
    """
    @staticmethod
    def __getattr__(k):
        res = KSR.pv.get(f"${k}")
        logger.debug("GET %s = %r", k, res)
        return res

    def __setattr__(self, k, v):
        if k[0]=="_":
            return super().__setattr__(k, v)
        logger.debug("SET %s = %r", k, v)
        if isinstance(v,int):
            KSR.pv.seti(f"${k}",v)
        else:
            KSR.pv.sets(f"${k}",v)

    @staticmethod
    def __delattr__(k):
        KSR.pv.unset(f"${k}")
PV=PV()

def key_fix(k):
    """Disambiguate and stringify a key"""
    if isinstance(k,int):
        return f"i:{k}"
    else:
        try:
            k=int(k)
        except ValueError:
            return k
        else:
            return f"s:{k}"

class _sub(_get):
    """
    Accessor class for one-level pseudovariables.

        class TYPE(_sub):
            what_ = "foo"
        TYPE=TYPE()

        TYPE.bar

    translates to `$foo(bar)`.

    """
    what_=None
    def _key(self, name):
        return f"${self.what_}({name})"

    def __getattr__(self, k):
        return self._get(self._key(k), ok=k)
        return res

    def __setattr__(self, k, v):
        if k[0]=="_":
            return super().__setattr__(k, v)
        self._set(self._key(k),v, ok=k)

    def _get(self, k, ok=None):
        res = KSR.pv.get(k)
        if ok is not None:
            logger.debug("GET %s %r = %r", ok, k, res)
        else:
            logger.debug("GET %r = %r", k, res)
        return res

    def _set(self, k,v, ok=None):
        if ok is not None:
            logger.debug("SET %s %r = %r", ok, k, v)
        else:
            logger.debug("SET %r = %r", k, v)

        if isinstance(v,int):
            KSR.pv.seti(k,v)
        else:
            KSR.pv.sets(k,v)

    def __delattr__(self, k):
        KSR.pv.unset(self._key(k))

class _sub_i(_get):
    """
    Helper for indexed one-level pseudovariables.

    DNS
    """
    def __init__(self, parent, i):
        self.parent = parent
        self.i = i

    def _key(self, name):
        return f"${parent.what_}=>{name}({self.i})"

class _subi:
    """
    Mix-in class where indexing with an integer yields a _sub_i.
    """
    def __getitem__(self, i):
        if not isinstance(i,int):
            return super().__getitem__(i)
        return _sub_i(self, i)

    def __setitem__(self, i, val):
        if not isinstance(i,int):
            return super().__setitem__(i,val)
        raise TypeError("You can only set an attribute of this")

    def __delitem__(self, i):
        if not isinstance(i,int):
            return super().__delitem__(i)
        raise TypeError("You can only set an attribute of this")

class _sub_s(_get):
    """
    Helper for indexed one-level pseudovariables.

    HDR
    """
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name

    def _key(self, i):
        return f"$({parent.what_}({self.name})[i])"


# AVP, XAVP: not useful for Python but used internally

class AVP(_sub):
    """
    AVP variables.

    Assigning does not push. Use explicit push/pop if reequired.
    """
    _what = "avp"

    def __setattr__(self,k,v):
        if k[0]=="_":
            return super().__setattr__(k, v)
        self._set(f"$({self._what}({k})[*]",v)

    def __delattr__(self,k):
        self._set(f"$({self._what}({k})[*]",None)

    def _push(self,k,v):
        super().__setattr__(k,v)

    def _pop(self, k):
        res = self.__getattr__(k)
        super().__setattr__(k,None)


class _xavp(_sub):
    def __init__(self,p,k):
        self._what = p._what
        self._k = k

    def _key(self, k):
        return f"${self._what}({self._k}=>{k})"
    def _topkey(self, k):
        return f"${self._what}({self._k}[0]=>{k})"

    def __setattr__(self, k, v):
        if k[0]=="_":
            return super().__setattr__(k, v)
        raise NotImplementedError("Modifying XAVPs is not yet(?) implemented")

    def __delattr__(self, k):
        raise NotImplementedError("Modifying XAVPs is not yet(?) implemented")

    def _push(self, **data):
        """
        Push a dict to this XAVP hash

        required e.g. for TLS
        """
        kp = self._key
        if not data:
            raise ValueError("need at least one key")
        for k,v in data.items():
            self._set(kp(k),v, ok=k)
            kp=self._topkey

class XAVP(_sub):
    """
    Rudimentary XAVP support.

    These things don't map at all well to Python (e.g. there's no way to enumerate keys)
    and setting a value auto-pushes. Thus this is read-only for now.
    """
    _what = "xavp"

    def __getattr__(self, k):
        return _xavp(self,k)

    def __setattr__(self, k, v):
        if k[0]=="_":
            return super().__setattr__(k, v)
        raise NotImplementedError("Modifying XAVPs is not yet(?) implemented")

    def _get(self, k):
        """
        Special method to return a single value
        """
        return super().__getattr__(k)

    def _set(self, k, v):
        """
        Set. Accepts a dict
        """
        raise NotImplementedError("Modifying XAVPs is not yet(?) implemented")

    def __delattr__(self, k):
        KSR.pv.xavm_rm(k)
XAVP=XAVP()

class XAVI(type(XAVP)):
    """Case-independent version of XAVP"""
    _what = "xavi"
XAVI=XAVI()


class EXPIRES(_sub):
    """
    .min, .max: expiry values for the current SIP message
    """
    what_="expires"
EXPIRES=EXPIRES()

class MSG(_sub):
    what_="msg"
MSG=MSG()

class VAR(_sub):
    what_="var"
VAR=VAR()

class SHV(_sub):
    what_="shv"
SHV=SHV()

class DSV(_sub):
    what_="dsv"
DSV=DSV()

class DEF(_sub):
    what_="def"
    def __getattr__(self, k):
        res = super().__getattr__(k)
        if res == "":
            res = True # "ifdef"-style tests
        return res

DEF=DEF()

class RDIR(_sub):
    what_="rdir"
RDIR=RDIR()

class STAT(_sub):
    what_="stat"
STAT=STAT()

class VERSION(_sub):
    what_="version"
VERSION=VERSION()

class SBRANCH(_sub):
    what_="sbranch"
SBRANCH=SBRANCH()

class SNDFROM(_sub):
    what_="sndfrom"
SNDFROM=SNDFROM()

class SNDTO(_sub):
    what_="sndto"
SNDTO=SNDTO()

class XAVU1(_sub):
    """
    XAVU access. This accesses single-level values. Use XAVU for two-level.
    """
    what_="xavu"
XAVU1=XAVU1()

class XAVU:
    """
    XAVU hashes.
    """
    what_ = "xavu"

    def __getattr__(self, i):
        return _sub_s(self, i)

    def __setattr__(self, i, val):
        if i[0]=="_":
            return super().__setattr__(i, val)
        raise TypeError("Use XAVU1 to access single entries")

    def __delattr__(self, i):
        raise TypeError("Use XAVU1 to access single entries")

_it=0
_it_lock = Lock()

def sym():
    """Generates a guaranteed-unique symbol."""
    with _it_lock():
        global _it
        _it += 1
        return f"i_{os.getpid()}_{_it}"

class _lookup_sub(_sub):
    def __init__(self, parent, args, kwargs):
        self.parent = parent
        self.args = args
        self.kwargs = kwargs
        self.sym = sym()

    def __enter__(self):
        if not self.parent.lookup_(self.sym, *self.args, **self.kwargs):
            raise RuntimeError(f"")
        return self

    def __exit__(self, *tb):
        self.parent.cleanup_(self.sym)

    def __iter__(self):
        for i in range(self[parent._count]):
            yield self[i]

class _lookup_subi(_subi,_lookup_sub):
    pass

class _lookup:
    """
    Provide the result of a lookup function.

    Override `lookup_` and possibly `cleanup_`.
    Both take a symbol as their first argument.

    `lookup_` should raise an exception if it didn't work.

    Usage::

        class DNS(_lookup):
            what_="dns"
            count_="count"

        with DNS("foo.bar") as res:
            for ri in res:
                print(ri.addr)
    """
    what_ = None
    count_ = "count"
    cls_ = _lookup_sub

    def lookup_(self, sym, *args, **kws):
        raise TypeError("override me")

    def cleanup_(self, sym):
        pass

    # internals

    def __call__(self, *a, **kw):
        return _lookup_sub(self, *a, **kw)


class DNS(_lookup):
    """
    Perform a DNS lookup, via ipops.dns_query.

    with DNS("test.example") as res:
        for ri in res:
            print(ri.addr)

    ... 
    >>> print(f"We have {res.count} results.")
    0
    >>> 
    """
    what_ = "dns"
    cls_ = _lookup_subi

    def lookup_(self, sym, name):
        return KSR.ipops.dns_query(name, sym)
DNS=DNS()

class SRV(_lookup):
    """
    Perform a SRV lookup, via ipops.srv_query.

    with SRV("test.example") as res:
        for ri in res:
            print(ri.target)

    ... 
    >>> print(f"We have {res.count} results.")
    0
    >>> 
    """
    what_ = "srvquery"
    cls_ = _lookup_subi

    def lookup_(self,sym,name):
        return KSR.ipops.srv_query(name,sym)
SRV = SRV()

class NAPTR(_lookup):
    """
    Perform a NAPTR lookup, via ipops.naptr_query.

    with NAPTR("test.example") as res:
        for ri in res:
            print(ri.services)

    ... 
    >>> print(f"We have {res.count} results.")
    0
    >>> 
    """
    what_ = "naptrquery"
    cls_ = _lookup_subi

    def lookup_(self,sym,name):
        return KSR.ipops.naptr_query(name,sym)
NAPTR = NAPTR()


class TLS(_sub):
    what_="tls"
TLS=TLS()

class MSRP(_sub):
    what_="msrp"
MSRP=MSRP()

class SIPT(_sub):
    what_="sipt_"
SIPT=SIPT()

class _sub_val(_get):
    """
    Helper for indexed pseudovariables.
    """
    def __init__(self, parent, name):
        self.parent = parent
        self.i = i

    def _key(self, name):
        return f"${parent.what_}=>{name}({self.i})"

class HDR(_get):
    """
    Access the (first) SIP header.

    Iterating this iterates over all headers. Requires "textopsx" module.

    Deleting removes the first header.
    """
    @staticmethod
    def __iter__(self):
        it = sym()
        KSR.textopsx.hf_iterator_start(it)
        try:
            while KSR.textopsx.hf_iterator_next(it):
                yield (KSR.textopsx.hf_iterator_hname(it),KSR.textopsx.hf_iterator_hbody(it))
        finally:
            KSR.textopsx.hf_iterator_end(it)

    def __delattr__(self,name):
        KSR.textopsx.remove_hf_value(name)
HDR=HDR()

class _HDRC(_get):
    what_ = "hdrc"
_HDRC=_HDRC()

class NHDR:
    """
    Access all headers, not just the first.

        NHDR.Via     -- array of Via headers
        del NHDR.Via -- drop all Via headers
    """
    what_ = "hdr"

    def __getattr__(self, i):
        return _sub_s(self, i)

    def __setattr__(self, i, val):
        if i[0]=="_":
            return super().__setattr__(i, val)
        raise TypeError("You can only get/delete an NHDR instance")

    def __delattr__(self, i):
        KSR.textops.remove_hf(i)

class BDY():
    @staticmethod
    def __iter__(self):
        it = sym()
        KSR.textopsx.bf_iterator_start(it)
        try:
            while KSR.textopsx.bf_iterator_next(it):
                yield PV(f"$bitval({it})")
        finally:
            KSR.textopsx.bf_iterator_end(it)

        return _bdy_iter()
BDY=BDY()

class SHT(_lookup):
    def lookup_(self, sym):
        KSR.htable.sht_iterator_start(it, self._what_)
        try:
            while KSR.htable.sht_iterator_next(it):
                yield (PV[f"$shtitkey({it})"], PV[f"$shtitval({it})"])
        finally:
            KSR.htable.sht_iterator_end(it)

    def keys_(self):
        for k,v in self.items_():
            yield k

    def values_(self):
        for k,v in self.items_():
            yield v

class SHT:
    def __getattr__(self, k):
        return _sht(k)
    # TODO add age_



SHT=SHT()

