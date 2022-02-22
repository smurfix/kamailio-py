## Kamailio - equivalent of routing blocks in Python
##
## KSR - the new dynamic object exporting Kamailio functions
## Router - the old object exporting Kamailio functions
##

import sys
sys.path.insert(0,"/root/kamailio-py")
from kamailio import var, thread_state, exit
from kamailio import log as log_
from kamailio.trace import trace

from pprint import pformat
import json
import logging

import KSR

VAR=var.VAR
DEF=var.DEF
PV=var.PV

# global variables corresponding to defined values (e.g., flags) in kamailio.cfg
FLT_ACC=1
FLT_ACCMISSED=2
FLT_ACCFAILED=3
FLT_NATS=5

FLB_NATB=6
FLB_NATSIPPING=7
BAD_AGENTS = {"friendly", "scanner", "sipcli", "sipvicious"}

from config import ip,SRC

# Global info logger, set in mod_init. TODO remove.
log = None

# global function to instantiate a kamailio class object
# -- executed when kamailio app_python module is initialized
def mod_init():
    log_.init(stderr=True)
    global log
    logger = logging.getLogger("main")
    log = logger.info
    return kamailio(logger=logger)


# -- {start defining kamailio class}
class kamailio:
    def __init__(self, logger=None):
        if logger is None:
            logger = lambda *a: 0
        self.log = logger

    # executed when kamailio child processes are initialized
    def child_init(self, rank):
        thread_state.setup(rank)
        return 0


    # SIP request routing. Cannot be renamed
    @trace
    def ksr_request_route(self, msg):
        self.log.debug("")
        self.log.debug("===== request [%s] from [%s]", PV.rm, PV.ru)
        log_.dump_obj(msg,"msg")

        sip=KSR.sipjson.sj_serialize("0B","$var(foo)")
        self.log.debug(pformat(json.loads(VAR.foo)))

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

    # Who needs databases …
    def route_static(self, msg):
        src = msg.src_address[0]
        try:
            src = SRC[src]
        except KeyError:
            return

        dstnr = PV.rU
        srcnr = PV.fU
        if len(srcnr) == 4 and (srcnr[0] in "12" or srcnr[0] == "0"):
            PV.fU = srcnr = f"+499119352{srcnr}"

        if src == "smurf":
            if len(dstnr) == 4 and (dstnr[0] in "12" or dstnr[0] == "0"):
                dstnr = f"+499119352{dstnr}"
            PV.ru = f"sip:{dstnr}@{ip.noris}:5060;transport=tcp"

        elif src == "noris":
            PV.ru = f"sip:{dstnr}@{ip.smurf}:5060;transport=tcp"

        else:
            return

        self.route_relay(msg)

        

    # wrapper around tm relay function
    def route_relay(self, msg):
        # enable additional event routes for forwarded requests
        # - serial forking, RTP relaying handling, a.s.o.
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

        sys.exit()


    # Per SIP request initial checks
    def route_reqinit(self, msg):
        if not KSR.is_myself(PV.si) and False: # WITH_ANTIFLOOD
            if not KSR.pv.is_null("$sht(ipban=>$si)"):
                # ip is already blocked
                self.log.debug("request from blocked IP - %s from %s (IP:%s:%s)",
                        PV.rm, PV.fu, PV.si, PV.sp)
                sys.exit()

            if hasattr(KSR,"pike") and KSR.pike.pike_check_req()<0:
                self.log.error(f"ALERT: pike blocking {PV.rm} from {PV.fu} (IP:{PV.si}:{PV.sp}")
                KSR.pv.seti("$sht(ipban=>$si)", 1)
                sys.exit()

        if KSR.corex.has_user_agent() > 0:
            ua = PV.ua
            if any(agent in ua for agent in BAD_AGENTS):
                KSR.sl.sl_send_reply(200, "Processed")
                sys.exit()

        if KSR.maxfwd.process_maxfwd(10) < 0:
            KSR.sl.sl_send_reply(483,"Too Many Hops")
            sys.exit()

        if KSR.is_OPTIONS():
#               and KSR.is_myself_ruri()
#               and KSR.corex.has_ruri_user() < 0):
            KSR.sl.sl_send_reply(200,"Keepalive")
            sys.exit()

        if KSR.sanity.sanity_check(1511, 7)<0:
            self.log.error(f"Malformed SIP message from {PV.si}:{PV.sp}")
            sys.exit()


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
            sys.exit()

        if KSR.is_ACK():
            if KSR.tm.t_check_trans() >0:
                # no loose-route, but stateful ACK
                # must be an ACK after a 487
                # or e.g. 404 from upstream server
                self.route_relay(msg)
                sys.exit()
            else:
                # ACK without matching transaction ... ignore and discard
                sys.exit()

        KSR.sl.sl_send_reply(404, "Not here")
        sys.exit()


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

        sys.exit()


    # User location service
    def route_location(self, msg):
        rc = KSR.registrar.lookup("location")
        if rc<0:
            KSR.tm.t_newtran()
            if rc==-1 or rc==-3:
                KSR.sl.send_reply(404, "Not Found")
                sys.exit()
            elif rc==-2:
                KSR.sl.send_reply(405, "Method Not Allowed")
                sys.exit()

        # when routing via usrloc, log the missed calls also
        if KSR.is_INVITE():
            KSR.setflag(FLT_ACCMISSED)

        self.route_relay(msg)
        sys.exit()



    # IP authorization and user uthentication
    def route_auth(self, msg):

        if not KSR.is_REGISTER():
            if hasattr(KSR,"permissions") and KSR.permissions.allow_source_address(1)>0:
                # source IP allowed
                return 1

        if KSR.is_REGISTER() or KSR.is_myself_furi():
            # authenticate requests
            if KSR.auth_db.auth_check(PV.fd, "subscriber", 1)<0:
                KSR.auth.auth_challenge(PV.fd, 0)
                sys.exit()

            # user authenticated - remove auth header
            if not KSR.is_method_in("RP"):
                KSR.auth.consume_credentials()

        # if caller is not local subscriber, then check if it calls
        # a local destination, otherwise deny, not an open relay here
        if (not KSR.is_myself_furi()) and (not KSR.is_myself_ruri()):
            KSR.sl.sl_send_reply(403,"Not relaying")
            sys.exit()


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
                if KSR.nathelper.nat_uac_test(8):
                    KSR.rtpengine.rtpengine_manage("SIP-source-address replace-origin replace-session-connection")
                else:
                    KSR.rtpengine.rtpengine_manage("replace-origin replace-session-connection");
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
        sys.exit()


    # Manage outgoing branches
    # -- equivalent of branch_route[...]{}
    @trace
    def branch_manage(self, msg):
        self.log.debug("")
        self.log.debug(f'===== new branch [{PV.T_branch_idx}] to {PV.ru}')
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
    # -- equivalent of reply_route{}
    @trace
    def reply_route(self, msg):
        self.log.debug("")
        self.log.debug("===== response %s", PV.rs)
        return 1

    # SIP send-on handling
    @trace
    def onsend_route(self, msg):
        self.log.debug("")
        self.log.debug("===== send_on")
        return 1


# -- {end defining kamailio class}
