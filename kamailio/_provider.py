"""
Class to hold provider data
"""

from ._util import match

try:
    from .var import SHV as _SHV
except ImportError:
    _SHV = {}

class Provider:
    """
    Settings for providers.

    Port=0: don't try to connect.
    """
    use_port = False

    def __init__(self,name,domain,addr, country,city,transport="tcp", flags=0, port=None, encrypt=False, encrypt_options="", display=None, plus=True, bare=False, route=(), pre_route=True, fallback=None, emergency=("110","112"), default="", a_in=None,b_in=None,a_out=None,b_out=None):
        if port is None:
            if transport == "tls":
                port = 5061
            else:
                port = 5060
        elif port == 0:
            self.use_port = True

        self._name = name
        self.domain = domain
        self.transport = transport
        self.addr = addr
        self.last_addr = addr[0] if isinstance(addr,(tuple,list)) else addr
        self.flags = flags
        self.port = port
        self.encrypt = encrypt
        self.encrypt_options = encrypt_options
        self.display = display
        self.plus = plus
        self.bare = bare
        self.country = str(country) if isinstance(country,int) else country
        self.city = str(city) if isinstance(city,int) else city
        self.pre_route = pre_route
        self.fallback = fallback
        self.emergency = emergency
        self.default = default
        self.routes = route
        self.a_in = a_in
        self.b_in = b_in
        self.a_out = a_out
        self.b_out = b_out

    @property
    def name(self):
        return self.domain.replace(".","_")

    @property
    def port(self):
        return _SHV[f"prov__{self.name}__port"]
    @port.setter
    def port(self, val):
        _SHV[f"prov__{self.name}__port"] = val

    @property
    def last_addr(self):
        return _SHV[f"prov__{self.name}__addr"]
    @last_addr.setter
    def last_addr(self, val):
        _SHV[f"prov__{self.name}__addr"] = val

    def route(self, nr:str) -> tuple[str,str]|None:
        for f in self.routes:
            r = match(f,nr)
            if r is not None:
                return r
        return None

    def format_a_in(self, nr) -> str:
        if nr == "anonymous":
            return self.default
        return self._format_in(nr, self.a_in)

    def format_b_in(self, nr) -> str:
        if nr in self.emergency:
            return nr
        return self._format_in(nr, self.b_in)

    def format_a_out(self, nr) -> str:
        return self._format_out(nr, self.a_out)

    def format_b_out(self, nr) -> str:
        if nr in self.emergency:
            return nr
        return self._format_out(nr, self.b_out)

    def _format_in(self, nr, fmt):
        """
        Rewrite an incoming number to CountryCityLocalExt form.
        """
        if isinstance(fmt,str):
            return fmt+nr
        if fmt is False:
            return nr
        if fmt is None:
            if nr.startswith("00"):
                return nr[2:]
            if nr.startswith("0"):
                return self.country + nr[1:]
            return self.country + self.city + nr

        if fmt is True:
            if nr.startswith("+"):
                return nr[1:]
            return nr

        # Ugh
        return "X"+str(fmt)+"X"+nr

    def _format_out(self, nr, fmt):
        """
        Rewrite a canoncical CountryCityLocalExt number to whatever the remote requires.
        """
        if fmt is False:
            return nr
        if fmt is None:
            return "00"+nr
        if fmt is True:
            return "+"+nr

        if isinstance(fmt,int):
            return nr[fmt:]

        # Ugh 2
        return "X"+str(fmt)+"X"+nr

    def __repr__(self):
        return f"Ext({self._name}: {self.transport} {self.addr})"
