"""
Config file analysis

The configuration is a YAML file::

    db: "/var/lib/kamailio/db.db"
    # special handling
    emergency:
    - "110"
    - "112"
    - "19222"
    self:
      domain: example.net
      country: "49"
      city: "69"
      prefix: "90009"
      default: "49911900090"


    setup:
    - kamailio.zoom.init
    zoom:
      prefix: zoom_
      api:
        key: myzoomapikeyfoobar
        secret: !secret zoom_client
      token: !secret zoom_token

    # pre-route is used for emergency numbers and similar.
    # If a source provider requires special handling, use its route instead
    pre-route:
    - match: "110|112"
      result: "$1"  # use provider's format_out if empty
      dest: "versa"

    route:
    - match: "4969(90009[0-2]*)"
      result: $1
      dest: "pbx"

    - match: "0{0,2}[1-9]"
      dest: "versa"

    provider:
      versa:
        # overrides the global table
        emergency:
        - "911"

        #
        domain: sip1.voip-1und1.net
        transport: tcp
        addr: "192.168.1.2"
        port: 5060
        flags: 0
        encrypt: false
        # encrypt_options: ""  # "SDES-no-AEAD_AES_256_GCM SDES-no-AEAD_AES_128_GCM …"
        reg:
          user: v_user
          pass: !secret v_pass

        # null: 0049911…, true: +49911…, false: 49911…
        # also in: string: prefix
        #      out: integer: cut off #num leading / use -#num trailing digits
        a_in: null
        b_in: null
        a_out: null
        b_out: null

        # use the pre-route filter?
        pre_route: true

        # the route is applied to untranslated B numbers of calls from this provider
        route:
        - match: "49(.*)"
          result: "49$1"  # use format_in if empty
          dest: zoom
          # if dest is given the number must be formatted for it
          # otherwise the result must be bare; route lookup will call format_out

        # Otherwise uses
        # - the setting of b_in to adapt the number, if no match
        # - the route: list to find the destination, if no dest
        # - b_out to format it, if no explicit result

      pbx1:
        transport: tcp
        domain: test.example.org
        addr: 10.11.12.13
        # other options for a second provider
        # The filter applies to incoming destination numbers

        a_in: true
        b_in: true

        filter:
        - match: "000(.*)"
          result: "$1"  # use b_in if empty
          dest: "zoom"  # use route table if empty

Internally phone numbers always are in 49911… format.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import suppress

import yaml

from ._provider import Provider
from ._util import match

k_global = ("emergency", "self", "setup")


class SecretLoader(yaml.SafeLoader):
    def __init__(self, secret, stream):
        self.secret = secret
        super().__init__(stream)


def load_secret(loader, node):
    return loader.secret[node.value]


SecretLoader.add_constructor("!secret", load_secret)


class UnknownProvider(ValueError):
    def __str__(self):
        return f"{self.args[0]!r} for {self.args[1]!r}"


class Cfg:
    def __init__(
        self,
        cfg="/etc/kamailio/config.yaml",
        secret="/etc/kamailio/secrets.yaml",  # noqa:S107
        test_load=False,
    ):
        with open(secret) as f:
            sec = yaml.SafeLoader(f).get_single_data()

        with open(cfg) as f:
            cfg = SecretLoader(sec, f).get_single_data()

        self.cfg = cfg

        if test_load:
            return

        for k in k_global:
            setattr(self, k, cfg[k])
        self.pre_routes = []
        self.routes = []

        for m in cfg.get("pre-route", ()):
            self.pre_routes.append(m)

        for m in cfg.get("route", ()):
            self.routes.append(m)

        self.provider = cfg.setdefault("provider", {})

        # change route destinations to point to providers directly
        def pfix(rt):
            m = rt["match"]
            if isinstance(m, int):
                raise ValueError("Match {m} must be a string")  # noqa:TRY004
            if "result" in rt and isinstance(rt["result"], int):
                raise ValueError(f"Result {rt['result']} must be a string")
            rt["match"] = re.compile(rt["match"])
            if (fn := rt.get("dest", None)) is not None:
                try:
                    rt["dest"] = self.provider[fn]
                except KeyError:
                    raise UnknownProvider(rt["match"].pattern, fn) from None

        try:
            dbp = cfg["database"]["path"]
        except KeyError:
            dbp = "/run/kamailio/db.sqlite"

        db = sqlite3.connect(dbp)
        try:
            cur = db.cursor()
            with suppress(sqlite3.OperationalError):
                cur.execute("drop table uacreg")
            cur.execute("""
                create table uacreg(
                    l_uuid, l_username, l_domain,
                    r_username, r_domain,
                    realm, auth_username, auth_password, auth_proxy,
                    expires)
                """)
            db.commit()

            for k, pd in self.provider.items():
                for kk, v in cfg["self"].items():
                    pd.setdefault(kk, v)
                reg = pd.pop("reg", None)
                if reg is not None:
                    s = self.cfg["self"]

                    ins = dict(
                        l_uuid="reg_" + k,
                        l_username="user_" + k,
                        l_domain=s["domain"],
                        r_username=pd.get("name", k),
                        r_domain=pd["domain"],
                        realm=pd.get("realm", pd["domain"]),
                        auth_username=pd["reg"]["user"],
                        auth_password=pd["reg"]["pass"],
                        auth_proxy=pd.get("proxy", pd["domain"]),
                        expires=pd.get("expires", 3600),
                    )
                    k1 = ", ".join(ins)
                    k2 = ", ".join(":" + x for x in ins)

                    cur.execute(f"insert into uacreg({k1}) values({k2})", ins)
                    db.commit()

                self.provider[k] = Provider(name=k, **pd)

            for rt in self.pre_routes:
                pfix(rt)
            for rt in self.routes:
                pfix(rt)
            for pd in self.provider.values():
                for rt in pd.routes:
                    pfix(rt)
                if pd.fallback is not None:
                    pd.fallback = self.provider[pd.fallback]

        finally:
            db.close()

    def __getitem__(self, k):
        return self.cfg[k]

    def route(self, nr: str, src: Provider) -> tuple[str, Provider]:
        """Translate B number+provider from source to destination.

        The A number is not part of this interface; it's
        subsequently formatted per the discovered provider.
        """
        dst = False
        if src.pre_route:
            for m in self.pre_routes:
                if (r := match(m, nr)) is not None:
                    dnr, dst = r
                    break

        if dst is False:
            if (r := src.route(nr)) is not None:
                dnr, dst = r

        if dst is False:
            dst = dnr = None

        if dnr is None:
            dnr = src.format_b_in(nr)

        fdnr = None
        if dst is None:
            for m in self.routes:
                if r := match(m, dnr):
                    fdnr, dst = r
                    break
            else:
                # no match at all.
                return None

        if src is dst and dst.fallback:
            dst = dst.fallback
        if fdnr is None:
            fdnr = dst.format_b_out(dnr)
        return fdnr, dst
