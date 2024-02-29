##
##
## KSR - the new dynamic object exporting Kamailio functions
## Router - the old object exporting Kamailio functions
##
##
## This is a sample implementation which 

import sys
sys.path.insert(0,"/root/kamailio-py")
from kamailio import var, thread_state
from kamailio import log as log_
from kamailio.trace import trace,trace_enable
from ursine.header import Header

from pprint import pformat
import json
import logging
import re
import time

import KSR

from urllib.parse import urlparse

exit = sys.exit  # *sigh*

re_savp = re.compile('^m=audio \\d+ RTP/SAVP ', re.MULTILINE)

VAR=var.VAR
DEF=var.DEF
PV=var.PV
XAVP=var.XAVP
XAVU1=var.XAVU1
HDR=var.HDR
HDRC=var.HDRC
NHDR=var.NHDR
SNDTO=var.SNDTO

# global variables corresponding to defined values (e.g., flags) in kamailio.cfg
FLT_ACC=1
FLT_ACCMISSED=2
FLT_ACCFAILED=3
FLT_NATS=5

FLB_NATB=6
FLB_NATSIPPING=7
BAD_AGENTS = {"friendly", "scanner", "sipcli", "sipvicious"}


# Global info logger, set in mod_init. TODO remove.
log = None

def user_from_url(url):
    u = urlparse(url).path
    at = u.find('@')
    if at > -1:
        u = u[:at]
    return u

# -- {start defining kamailio class}
class Kamailio:
    def __init__(self, cfg, logger=None):
        self.cfg = cfg
        if logger is None:
            logger = lambda *a: 0
        self.log = logger

        self.SRC = {}
        for k,v in self.cfg.provider.items():
            if isinstance(v.addr,(list,tuple)):
                for vv in v.addr:
                    self.SRC[vv] = k
            else:
                self.SRC[v.addr] = k


    # executed when kamailio child processes are initialized
    def child_init(self, rank):
        thread_state.setup(rank)
        return 0

    def background(self, txt, ttt):
        i=0
        while True:
            print("BG",i,txt)
            time.sleep(10)
            i += 1

    # SIP request routing. Cannot be renamed
    @trace
    def ksr_request_route(self, msg):
        if PV.rm != "OPTIONS":
            self.log.info("")
            self.log.info("===== request [%s] to [%s] from [%s] (%s)\n%s", PV.rm, PV.ru, PV.fu, PV.si, PV.mb)

        KSR.sipjson.sj_serialize("0B","$var(debug_json)")
        self.log.debug("Data:\n%s",pformat(json.loads(VAR.debug_json)))

        # per request initial checks
        self.route_reqinit(msg)

        # NAT detection
        self.route_natdetect(msg)

        # CANCEL processing
        if KSR.is_CANCEL():
            if KSR.tm.t_check_trans()>0:
                self.route_relay(msg)
            return 1

        # handle requests within SIP dialogs
        self.route_withindlg(msg)

        # -- only initial requests (no To tag)

        # handle retransmissions
        if KSR.tmx.t_precheck_trans()>0:
            KSR.tm.t_check_trans()
            return 1

        if KSR.tm.t_check_trans()==0:
            return 1

        self.fix_contact(msg)

        # authentication
        self.route_auth(msg)

        # record routing for dialog forming requests (in case they are routed)
        # - remove preloaded route headers
        KSR.hdr.remove("Route")
        if KSR.is_method_in("IS"):
            KSR.rr.record_route()


        # account only INVITEs
        if PV.rm == "INVITE":
            KSR.setflag(FLT_ACC); # do accounting


        # dispatch requests to foreign domains
        self.route_sipout(msg)

        # # requests for my local domains

        # handle registrations
        self.route_registrar(msg)

        if KSR.corex.has_ruri_user() < 0:
            # request with no Username in RURI
            KSR.sl.sl_send_reply(484,"Address Incomplete")
            return 1

        # fake it
        self.route_static(msg)

        # user location service
        self.route_location(msg)

        return 1

    def fix_contact(self, msg):
        if PV.rm != "INVITE":
            return

        src = msg.src_address[0]
        try:
            src = self.SRC[src]
        except KeyError:
            return

        srcnr = PV.fU
        snr = src.format_a_in(srcnr)

        if HDRC.Contact > 0:
            h=Header(HDR.Contact)
            if h.uri.user != snr:
                HDR.Contact = str(h.with_uri(h.uri.with_user(snr)))

    def route_static(self, msg):
        if self.fix_addrs(msg):
            self.route_relay(msg, True)


    def fix_addrs(self, msg):
        src = msg.src_address[0]
        try:
            src = self.SRC[src]
        except KeyError:
            return 0

        srcnr = PV.fU
        dstnr = PV.rU

        self.log.info("Data:\n%s",pformat(json.loads(VAR.debug_json)))

        snr = src.format_a_in(srcnr)
        dst = self.cfg.route(dstnr,src)
        if dst:
            dnr,dst = dst
            snr = dst.format_a_out(snr)
        else:
            dstnr = None

        self.log.debug("ROUTE from %r: %s to %r: %s",snr,src, dstnr, dst)

        destfU = None
        if snr != srcnr:
            destfU = snr
        if dnr != dstnr:
            PV.tU = dnr
        if PV.fu == "":  # !!
            PV.fu = snr  # !!
        if PV.ai and "anonymous" not in PV.ai:
            uu = user_from_url(PV.ai)
            self.log.info("want fu AI %s %s =%s", PV.fu, PV.ai, uu)
#           PV.fu = PV.ai
            destfU = uu
        if PV.fU == "" or PV.fU == "anonymous":
            self.log.info("set fU ANON1 %s %s", PV.fU, snr)
            destfU = snr
        if PV.tu == "":
            self.log.info("set TU EMPTY %s",dnr)
            PV.tu = dnr

        self.log.debug("ROUTE from %r: %s to %r: %s",snr,src, dstnr, dst)
        if dst is None:
            return 0
        if src is dst:
            return 0

        XAVU1.call_src = PV.siz
        XAVU1.src_encrypt = src.encrypt or 0
        XAVU1.dst_encrypt = dst.encrypt or 0
        XAVU1.src_encrypt_opt = src.encrypt_options or ""
        XAVU1.dst_encrypt_opt = dst.encrypt_options or ""
        if dst.transport == "tls":
            XAVP["tls"]._push(server_name=dst.domain, server_id=dst.domain)
#       if not dst.port:
#           self.log.warning("Provider %s doesn't have a port", dst.domain)
#           KSR.sl.sl_send_reply(480, "No link")
#           exit()
#       elif dst.use_port:
#           PV.fsn = f"s_{dst.transport}"

        nru = f"sip:{dnr}@{dst.last_addr}:{dst.port};transport={dst.transport}"
        self.log.info("set tu %s %s", PV.fU, nru)
        PV.ru = nru

# probably not, wrong prov
#       ntu = f"sip:{dstnr}@{dst.last_addr}"
#       self.log.info("want tu %s %s", PV.tu, ntu)
#       PV.tu = ntu

        self.log.info("set tU %s %s", PV.tU, dnr)
        PV.tU = dnr

        self.log.info("set rU %s %s", PV.rU, dnr)
        PV.rU = dnr

        if PV.fu == "" or "anonymous" in PV.fu:
            nfu = f"sip:{snr}@{src.last_addr}"
            self.log.info("want fu ANON %s %s",PV.fu, nfu)
            self.log.info("set fU ANON %s %s",PV.fU, snr)
#           PV.fu = nfu
            destfU = snr

        if destfU is not None:
            PV.fU = destfU
        if PV.fn == "anonymous" and src.display is not None:
            PV.fn = src.display

        KSR.sipjson.sj_serialize("0B","$var(debug_json)")
        self.log.info("Result:\n%s",pformat(json.loads(VAR.debug_json)))

        PV.td = dst.domain
        return 1


    # wrapper around tm relay function
    def route_relay(self, msg, fixed=False):
        # enable additional event routes for forwarded requests
        # - serial forking, RTP relaying handling, a.s.o.

        if not fixed and KSR.is_method_in("I"):
            self.fix_addrs(msg)

        if KSR.is_method_in("IBSU"):
            if KSR.tm.t_is_set("branch_route")<0:
                KSR.tm.t_on_branch("branch_manage")

        if KSR.is_method_in("ISU"):
            if KSR.tm.t_is_set("onreply_route")<0:
                KSR.tm.t_on_reply("onreply_manage")

        if KSR.is_INVITE():
            if KSR.tm.t_is_set("failure_route")<0:
                KSR.tm.t_on_failure("failure_manage")

        if KSR.tm.t_relay()<0:
            self.log.debug("failed to relay");
            KSR.sl.sl_reply_error()

        exit()


    # Per SIP request initial checks
    def route_reqinit(self, msg):
        if not KSR.is_myself(PV.si) and False: # WITH_ANTIFLOOD
            if not KSR.pv.is_null("$sht(ipban=>$si)"):
                # ip is already blocked
                self.log.debug("request from blocked IP - %s from %s (IP:%s:%s)",
                        PV.rm, PV.fu, PV.si, PV.sp)
                exit()

            if hasattr(KSR,"pike") and KSR.pike.pike_check_req()<0:
                self.log.error(f"ALERT: pike blocking {PV.rm} from {PV.fu} (IP:{PV.si}:{PV.sp}")
                KSR.pv.seti("$sht(ipban=>$si)", 1)
                exit()

        if KSR.corex.has_user_agent() > 0:
            ua = PV.ua
            if any(agent in ua for agent in BAD_AGENTS):
                KSR.sl.sl_send_reply(200, "Processed")
                exit()

        if KSR.maxfwd.process_maxfwd(10) < 0:
            KSR.sl.sl_send_reply(483,"Too Many Hops")
            exit()

        if KSR.is_OPTIONS():
#               and KSR.is_myself_ruri()
#               and KSR.corex.has_ruri_user() < 0):
            src = msg.src_address[0]
            try:
                src = self.cfg.provider[self.SRC[src]]
            except KeyError:
                self.log.warning(f"{src}: not found")
            else:
                if src.use_port:
                    src.port = PV.sp
                    src.last_addr = PV.siz
#                   self.log.info(f"{src.domain}: Use port {src.last_addr}:{src.port}")
#               else:
#                   self.log.info(f"{src.domain}: Use port is off")

            KSR.sl.sl_send_reply(200,"Keepalive")
            exit()

        if KSR.sanity.sanity_check(1511, 7)<0:
            self.log.error(f"Malformed SIP message from {PV.si}:{PV.sp}")
            exit()


    # Handle requests within SIP dialogs
    def route_withindlg(self, msg):
        if KSR.siputils.has_totag()<0:
            return 1

        # sequential request withing a dialog should
        # take the path determined by record-routing
        if KSR.rr.loose_route()>0:
            self.route_dlguri(msg)
            if KSR.is_BYE():
                # do accounting ...
                KSR.setflag(FLT_ACC)
                # ... even if the transaction fails
                KSR.setflag(FLT_ACCFAILED)
            elif KSR.is_ACK():
                # ACK is forwarded statelessly
                self.route_natmanage(msg)
            elif KSR.is_NOTIFY():
                # Add Record-Route for in-dialog NOTIFY as per RFC 6665.
                KSR.rr.record_route()

            self.route_relay(msg)
            exit()

        if KSR.is_ACK():
            if KSR.tm.t_check_trans() >0:
                # no loose-route, but stateful ACK
                # must be an ACK after a 487
                # or e.g. 404 from upstream server
                self.route_relay(msg)
                exit()
            else:
                # ACK without matching transaction ... ignore and discard
                exit()

        KSR.sl.sl_send_reply(404, "Not here")
        exit()


    # Handle SIP registrations
    def route_registrar(self, msg):
        if not KSR.is_REGISTER():
            return 1
        if KSR.isflagset(FLT_NATS):
            KSR.setbflag(FLB_NATB)
            # do SIP NAT pinging
            KSR.setbflag(FLB_NATSIPPING)

        if KSR.registrar.save("location", 0)<0:
            KSR.sl.sl_reply_error()

        exit()


    # User location service
    def route_location(self, msg):
        rc = KSR.registrar.lookup("location")
        if rc<0:
            self.log.info("Lookup fails with %s", rc)
            KSR.tm.t_newtran()
            if rc==-1 or rc==-3:
                KSR.sl.send_reply(404, "Not Found")
                exit()
            elif rc==-2:
                KSR.sl.send_reply(405, "Method Not Allowed")
                exit()
            else:
                KSR.sl.send_reply(405, "Method Not Allowed")
                exit()

        # when routing via usrloc, log the missed calls also
        if KSR.is_INVITE():
            KSR.setflag(FLT_ACCMISSED)

        self.route_relay(msg)
        exit()


    # IP authorization and user authentication.
    def route_auth(self, msg):
        # Known providers are skipped here.
        try:
            src = self.SRC[msg.src_address[0]]
        except KeyError:
            pass
        else:
            return

        if not KSR.is_REGISTER():
            if hasattr(KSR,"permissions") and KSR.permissions.allow_source_address(1)>0:
                # source IP allowed
                return 1

        if KSR.is_REGISTER() or KSR.is_myself_furi():
            # authenticate requests
            auth = getattr(KSR, "auth", None)
            if auth is not None:
                auth_db = getattr(KSR, "auth_db", None)
                if auth_db is not None and auth_db.auth_check(PV.fd, "subscriber", 1)<0:
                    auth.auth_challenge(PV.fd, 0)
                    exit()

                # user authenticated - remove auth header
                if not KSR.is_method_in("RP"):
                    auth.consume_credentials()

        # if caller is not local subscriber, then check if it calls
        # a local destination, otherwise deny, not an open relay here
        if (not KSR.is_myself_furi()) and (not KSR.is_myself_ruri()):
            KSR.sl.sl_send_reply(403,"Not relaying")
            exit()


    # Caller NAT detection
    def route_natdetect(self, msg):
        KSR.force_rport()
        if hasattr(KSR,"nathelper") and KSR.nathelper.nat_uac_test(19)>0:
            if KSR.is_REGISTER():
                KSR.nathelper.fix_nated_register()
            elif KSR.siputils.is_first_hop()>0:
                KSR.nathelper.set_contact_alias()

            KSR.setflag(FLT_NATS)


    # RTPProxy control
    def route_natmanage(self, msg):
        if KSR.siputils.is_request()>0:
            if KSR.siputils.has_totag()>0:
                if KSR.rr.check_route_param("nat=yes")>0:
                    KSR.setbflag(FLB_NATB)

        if (not (KSR.isflagset(FLT_NATS) or KSR.isbflagset(FLB_NATB))):
            return

        if DEF.WITH_NAT:
            if DEF.WITH_RTPENGINE:
                if XAVU1.call_src == PV.siz:
                    enc = XAVU1.dst_encrypt
                else:
                    enc = XAVU1.src_encrypt
                src_opt = XAVU1.src_encrypt_opt or ""
                dst_opt = XAVU1.dst_encrypt_opt or ""
                if enc:
                    opt = "RTP/SAVP"
                else:
                    opt = "RTP/AVP"
                opt = f"{opt} {src_opt} {dst_opt}"

                if KSR.nathelper.nat_uac_test(8):
                    # SIP-source-address
                    opt = f"trust-address replace-origin replace-session-connection {opt}"
                else:
                    opt = f"replace-origin replace-session-connection {opt}"
                self.log.debug("RTP engine: %s", opt)
                KSR.rtpengine.rtpengine_manage(opt)
            else:
                if KSR.nathelper.nat_uac_test(8):
                    KSR.rtpproxy.rtpproxy_manage("co")
                else:
                    KSR.rtpproxy.rtpproxy_manage("cor")

        if KSR.siputils.is_request()>0:
            if not KSR.siputils.has_totag():
                if KSR.tmx.t_is_branch_route()>0:
                    KSR.rr.add_rr_param(";nat=yes")

        if KSR.siputils.is_reply()>0:
            if KSR.isbflagset(FLB_NATB):
                KSR.nathelper.set_contact_alias()

        return 1


    # URI update for dialog requests
    def route_dlguri(self, msg):
        if not KSR.isdsturiset():
            KSR.nathelper.handle_ruri_alias()

        return 1


    # Routing to foreign domains
    def route_sipout(self, msg):
        if KSR.is_myself_ruri():
            return 1

        KSR.hdr.append("P-Hint: outbound\r\n")
        self.route_relay(msg)
        exit()


    # Manage outgoing branches
    # -- equivalent of branch_route[...]{}
    @trace
    def branch_manage(self, msg):
        self.log.debug("")
        self.log.debug(f'===== new branch [{PV.T_branch_idx}] to {PV.ru}')

#       src = msg.src_address[0]
#       try:
#           src = self.SRC[src]
#       except KeyError:
#           pass
#       else:
#           srcnr = PV.fU
#           snr = src.format_a_in(srcnr)
#           if HDRC.Contact > 0:
#               h=Header(HDR.Contact)
#               if h.uri.user != snr:
#                   HDR.Contact = str(h.with_uri(h.uri.with_user(snr)))

        self.route_natmanage(msg)
        return 1


    # Manage incoming replies
    # -- equivalent of onreply_route[...]{}
    @trace
    def onreply_manage(self, msg):
        scode = PV.rs
        self.log.debug("")
        self.log.debug(f"===== reply: %s", scode)
        if scode>100 and scode<299:
            self.route_natmanage(msg)

        return 1


    # Manage failure routing cases
    # -- equivalent of failure_route[...]{}
    @trace
    def failure_manage(self, msg):
        self.log.debug("")
        self.log.debug(f"===== Failure: %s", PV.rs)
        self.route_natmanage(msg)

        if KSR.tm.t_is_canceled()>0:
            return 1

        return 1


    # SIP response handling
    @trace
    def reply_route(self, msg):
        self.log.info("")
        self.log.info("===== reply %s (%s)\n%s", PV.rs, PV.si, PV.mb)
        return 1

    # SIP send-on handling
    @trace
    def onsend_route(self, msg):
        self.log.info("")
        self.log.info("===== send_on to %s:%d\n%s", SNDTO.ip, SNDTO.port, SNDTO.buf)
        return 1

    def tls_event(self, msg):
        self.log.info("")
        self.log.info("===== TLS %r", msg)
        return 1

    def event_route(self, *msg):
        self.log.info("")
        self.log.info("===== Event %r", msg)
        return 1

# global function to instantiate a kamailio class object
# -- executed when kamailio app_python module is initialized
def mod_init(Base=Kamailio):
    log_.init(stderr=True)
    global log
    logger = logging.getLogger("main")
    log = logger.info
    trace_enable(DEF.WITH_PYTRACE)

    from ._config import Cfg
    cfg = Cfg("/etc/kamailio/config.yaml")
    return Base(cfg, logger=logger)

