## Kamailio - equivalent of routing blocks in Python
##
## KSR - the new dynamic object exporting Kamailio functions
## Router - the old object exporting Kamailio functions
##

## Relevant remarks:
##  * return code -255 is used to propagate the 'exit' behaviour to the
##  parent route block function. The alternative is to use the native
##  Python function sys.exit() (or exit()) -- it throws an exception that
##  is caught by Kamailio and previents the stop of the interpreter.


import sys
sys.path.insert(0,"/root/kamailio-py")
from kamailio import var, thread_state
from kamailio import log as log_
from kamailio.trace import trace

from pprint import pformat
import json
import logging

import KSR

VAR=var.VAR

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

# global function to instantiate a kamailio class object
# -- executed when kamailio app_python module is initialized
def mod_init():
    log_.init(stderr=True)
    global log
    logger = logging.getLogger("main")
    log = logger.info
    return minit(logger)

def minit(logger):
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
        log("===== request - from kamailio python script")
        log("===== method [%s] r-uri [%s]", KSR.pv.get("$rm"),KSR.pv.get("$ru"))
        log_.dump_obj(msg,"msg")

        sip=KSR.sipjson.sj_serialize("0B","$var(foo)")
        log(pformat(json.loads(VAR.foo)))

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
        if KSR.pv.get("$rm")=="INVITE":
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


        # user location service
        self.route_location(msg)

        return 1


    # wrapper around tm relay function
    def route_relay(self, msg):
        # enable additional event routes for forwarded requests
        # - serial forking, RTP relaying handling, a.s.o.
        if KSR.is_method_in("IBSU"):
            log("check branch",KSR.tm.t_is_set("branch_route"))
            if KSR.tm.t_is_set("branch_route")<0:
                KSR.tm.t_on_branch("ksr_branch_manage")

        if KSR.is_method_in("ISU"):
            log("check onreply",KSR.tm.t_is_set("onreply_route"))
            if KSR.tm.t_is_set("onreply_route")<0:
                KSR.tm.t_on_reply("ksr_onreply_manage")

        if KSR.is_INVITE():
            log("check fail",KSR.tm.t_is_set("failure_route"))
            if KSR.tm.t_is_set("failure_route")<0:
                KSR.tm.t_on_failure("ksr_failure_manage")

        if KSR.tm.t_relay()<0:
            log("fail");
            KSR.sl.sl_reply_error()

        sys.exit()


    # Per SIP request initial checks
    def route_reqinit(self, msg):
        if not KSR.is_myself(KSR.pv.get("$si")) and False: # WITH_ANTIFLOOD
            if not KSR.pv.is_null("$sht(ipban=>$si)"):
                # ip is already blocked
                KSR.dbg("request from blocked IP - " + KSR.pv.get("$rm")
                        + " from " + KSR.pv.get("$fu") + " (IP:"
                        + KSR.pv.get("$si") + ":" + str(KSR.pv.get("$sp")) + ")\n")
                sys.exit()

            if hasattr(KSR,"pike") and KSR.pike.pike_check_req()<0:
                KSR.err("ALERT: pike blocking " + KSR.pv.get("$rm")
                        + " from " + KSR.pv.get("$fu") + " (IP:"
                        + KSR.pv.get("$si") + ":" + str(KSR.pv.get("$sp")) + ")\n")
                KSR.pv.seti("$sht(ipban=>$si)", 1)
                sys.exit()

        if KSR.corex.has_user_agent() > 0:
            ua = KSR.pv.gete("$ua")
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
            KSR.err("Malformed SIP message from "
                    + KSR.pv.get("$si") + ":" + str(KSR.pv.get("$sp")) +"\n")
            sys.exit()


    # Handle requests within SIP dialogs
    def route_withindlg(self, msg):
        if KSR.siputils.has_totag()<0:
            return 1

        # sequential request withing a dialog should
        # take the path determined by record-routing
        if KSR.rr.loose_route()>0:
            if self.route_dlguri(msg)==-255:
                sys.exit()
            if KSR.is_BYE():
                # do accounting ...
                KSR.setflag(FLT_ACC)
                # ... even if the transaction fails
                KSR.setflag(FLT_ACCFAILED)
            elif KSR.is_ACK():
                # ACK is forwarded statelessly
                if self.route_natmanage(msg)==-255:
                    sys.exit()
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
            if KSR.auth_db.auth_check(KSR.pv.get("$fd"), "subscriber", 1)<0:
                KSR.auth.auth_challenge(KSR.pv.get("$fd"), 0)
                sys.exit()

            # user authenticated - remove auth header
            if not KSR.is_method_in("RP"):
                KSR.auth.consume_credentials()

        # if caller is not local subscriber, then check if it calls
        # a local destination, otherwise deny, not an open relay here
        if (not KSR.is_myself_furi()) and (not KSR.is_myself_ruri()):
            KSR.sl.sl_send_reply(403,"Not relaying")
            sys.exit()

        return 1


    # Caller NAT detection
    def route_natdetect(self, msg):
        KSR.force_rport()
        if hasattr(KSR,"nathelper") and KSR.nathelper.nat_uac_test(19)>0:
            if KSR.is_REGISTER():
                KSR.nathelper.fix_nated_register()
            elif KSR.siputils.is_first_hop()>0:
                KSR.nathelper.set_contact_alias()

            KSR.setflag(FLT_NATS)

        return 1


    # RTPProxy control
    def route_natmanage(self, msg):
        if KSR.siputils.is_request()>0:
            if KSR.siputils.has_totag()>0:
                if KSR.rr.check_route_param("nat=yes")>0:
                    KSR.setbflag(FLB_NATB)

        if (not (KSR.isflagset(FLT_NATS) or KSR.isbflagset(FLB_NATB))):
            return 1

        KSR.rtpproxy.rtpproxy_manage("co")

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
    def branch_manage(self, msg):
        KSR.dbg(f'new branch [{KSR.pv.get("$T_branch_idx")}] to {KSR.pv.get("$ru")}\n')
        self.route_natmanage(msg)
        return 1


    # Manage incoming replies
    # -- equivalent of onreply_route[...]{}
    def onreply_manage(self, msg):
        KSR.dbg("incoming reply\n")
        scode = KSR.pv.get("$rs")
        if scode>100 and scode<299:
            self.route_natmanage(msg)

        return 1


    # Manage failure routing cases
    # -- equivalent of failure_route[...]{}
    def failure_manage(self, msg):
        if self.route_natmanage(msg)==-255 : return 1

        if KSR.tm.t_is_canceled()>0:
            return 1

        return 1


    # SIP response handling
    # -- equivalent of reply_route{}
    def reply_route(self, msg):
        log("===== response - from kamailio python script")
        return 1


# -- {end defining kamailio class}
