import conf
import api
import re
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.app.wsgi import WSGIApplication
from ryu.lib import hub


class DynamicACL(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet, 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(DynamicACL, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.protected_mac_list = set()
        wsgi = kwargs['wsgi']
        self.dpset = kwargs['dpset']
        wsgi.register(api.DynamicACLController, {conf.INSTANCE_NAME: self})
        self._load_protected_mac_file()
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev) -> None:
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.logger.info('[state_change_handler] - register datapath: %i', datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.logger.info('[state_change_handler] - unregister datapath: %i', datapath.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port.setdefault(datapath.id, {})

        self.logger.info('[switch_features_handler] - '
                         'datapath_id=%i n_buffers=%d '
                         'n_tables=%d auxiliary_id=%d '
                         'capabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        # Always allow ARP with high priority to avoid network lockdown
        self._add_flow(datapath, conf.ARP_PRI, parser.OFPMatch(eth_type=0x806),
                       [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])
        self._add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev) -> None:
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        eth_dst = eth.dst
        eth_src = eth.src

        if eth_dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth_dst]
            # install a flow to avoid packet_in next time
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self._add_flow(datapath, conf.LEARN_PRI, match,
                           actions, 0, conf.LEARN_IDLE_TIMEOUT)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[datapath.id][eth_src] = in_port

        if eth_dst in self.protected_mac_list and self.mac_to_port[datapath.id].get(eth_dst, None):
            self.logger.info("[packet_in_handler] - Request to protected device: %s from: %s", eth_dst, eth_src)
            self._add_isolated_path(eth_src, eth_dst)
            return
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            self._load_protected_mac_file()

        if ipv4_pkt:
            self.logger.debug("[packet_in_handler] - datapath_id=%i, eth_src: %s, eth_dst: %s, ip_src: %s, ip_dst: %s, in_port: %s",
                             datapath.id, eth_src, eth_dst,  ipv4_pkt.src, ipv4_pkt.dst, in_port)
        else:
            self.logger.debug("[packet_in_handler] - datapath_id=%i, eth_src: %s, eth_dst: %s, in_port: %s",
                             datapath.id, eth_src, eth_dst, in_port)

        match = parser.OFPMatch(in_port=in_port)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev) -> None:
        isolated_devices = {}

        for stat in ev.msg.body:
            if stat.cookie == conf.ISOLATION_COOKIE_ID:
                match = stat.match
                oxm_fields = match.to_jsondict()["OFPMatch"]["oxm_fields"]
                mac_address = None

                for oxm_field in oxm_fields:
                    oxm_field_name = oxm_field["OXMTlv"]["field"]
                    oxm_value = oxm_field["OXMTlv"]["value"]
                    if "eth_" in oxm_field_name and oxm_value not in self.protected_mac_list:
                        mac_address = oxm_value
                        isolated_dev = isolated_devices.get(
                            mac_address, {"flow_count": 0, "flow_match": []})
                        isolated_dev["flow_count"] += 1
                        isolated_dev["flow_match"].append(match)
                        isolated_devices[mac_address] = isolated_dev

        for _key, _val in isolated_devices.items():
            if _val["flow_count"] < 3:
                for match in _val["flow_match"]:
                    self.logger.warning("[flow_stats_reply_handler] - The device \"%s\" has encountered matched dead flows and will be removed", _key)
                    self._remove_dead_flows(ev.msg.datapath, match)

    def _add_flow(self, datapath, priority, match, actions: list, cookie: int = 0, idle: int = 0, buffer_id=None) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
                                    match=match, idle_timeout=idle, instructions=inst)
        datapath.send_msg(mod)

    def _remove_dead_flows(self, datapath, match) -> None:
        ofproto = datapath.ofproto
        instructions = []

        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        datapath.send_msg(flow_mod)

    def _remove_flows_by_cookie_id(self, cookie_id: int) -> None:
        for datapath in self.dpset.get_all():
            datapath = datapath[1]
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch()
            flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, cookie=cookie_id,
                                                          cookie_mask=0xFFFFFFFFFFFFFFFF, table_id=0, command=ofproto.OFPFC_DELETE,
                                                          out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                                          match=match, instructions=[])
            datapath.send_msg(flow_mod)

    def _add_protection_flows(self) -> None:
        self._remove_flows_by_cookie_id(conf.PROTECTED_SRV_COOKIE_ID)
        for datapath in self.dpset.get_all():
            datapath = datapath[1]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            for mac in self.protected_mac_list:
                if self.mac_to_port[datapath.id].get(mac, None):
                    self._add_flow(datapath, conf.PROTECTED_SRV_PRI, parser.OFPMatch(eth_dst=mac),
                                   [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)], conf.PROTECTED_SRV_COOKIE_ID)
                    self._add_flow(datapath, conf.PROTECTED_SRV_PRI, parser.OFPMatch(eth_src=mac),
                                   [], conf.PROTECTED_SRV_COOKIE_ID)
                else:
                    self.logger.debug("[add_protection_flows] - unknown port number for %s", mac)

    def _add_isolated_path(self, eth_src: str, eth_dst: str) -> None:
        for datapath in self.dpset.get_all():
            datapath = datapath[1]
            parser = datapath.ofproto_parser

            eth_src_port = self.mac_to_port[datapath.id].get(eth_src, None)
            eth_dst_port = self.mac_to_port[datapath.id].get(eth_dst, None)

            self.logger.info("[add_isolated_path] - Adding isolated path for: %s to: %s", eth_src, eth_dst)

            if eth_src_port and eth_dst_port:
                # connection initiator to protected device flow
                self._add_flow(datapath, conf.ISOLATION_PRI, parser.OFPMatch(in_port=eth_src_port, eth_src=eth_src, eth_dst=eth_dst),
                               [parser.OFPActionOutput(eth_dst_port)], conf.ISOLATION_COOKIE_ID, conf.ISOLATION_IDLE_TIMEOUT)
                # protected device to connection initiator flow
                self._add_flow(datapath, conf.ISOLATION_PRI, parser.OFPMatch(in_port=eth_dst_port, eth_src=eth_dst, eth_dst=eth_src),
                               [parser.OFPActionOutput(eth_src_port)], conf.ISOLATION_COOKIE_ID, conf.ISOLATION_IDLE_TIMEOUT)
                # block other connections of the initiator without timeout, stats will remove it
                self._add_flow(datapath, conf.ISOLATION_PRI, parser.OFPMatch(in_port=eth_src_port, eth_src=eth_src),
                               [], conf.ISOLATION_COOKIE_ID)
            else:
                self.logger.warning("[add_isolated_path] - Unable to add isolated path, port not found")

    def _add_protected_device(self, mac) -> bool:
        # check is valid mac address
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
            try:
                self.protected_mac_list.add(mac)
                if not self._update_protected_mac_file():
                    self.logger.error("[add_protected_device] - Unable to update protected devices file")
                self._add_protection_flows()
            except Exception as exception:
                self.protected_mac_list.discard(mac)
                self._load_protected_mac_file()
                self.logger.error("[add_protected_device_exception] - %s", str(exception))
            else:
                return True
        return False

    def _remove_protected_device(self, mac) -> bool:
        # check is valid mac address
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
            try:
                self.protected_mac_list.discard(mac)
                if not self._update_protected_mac_file():
                    self.logger.error("[reomve_protected_device] - Unable to update protected devices file")
                self._add_protection_flows()
            except Exception as exception:
                self.logger.error("[reomve_protected_device_exception] - %s", str(exception))
                self._load_protected_mac_file()
            else:
                return True
        return False

    def _update_protected_mac_file(self) -> bool:
        try:
            protected_mac_list_file = open(f"{conf.TMP_PATH}/protected_mac_list", "w+", encoding="utf-8")
            for protected_mac in self.protected_mac_list:
                protected_mac_list_file.write(protected_mac + "\n")
        except Exception as exception:
            self.logger.error("[update_protected_mac_file_exception] - %s", str(exception))
        else:
            return True
        return False

    def _load_protected_mac_file(self) -> bool:
        count = 0
        try:
            protected_mac_list_file = open(
                f"{conf.TMP_PATH}/protected_mac_list", "r", encoding="utf-8")
            macs = protected_mac_list_file.readlines()
            for mac in macs:
                if self._add_protected_device(mac.strip()):
                    count += 1
            self._add_protection_flows()
            self.logger.debug("[load_protected_mac_file] - A total of %i devices have been included in the list of protected devices", count)
        except Exception as exception:
            self.logger.error("[load_protected_mac_file_exception] - %s", str(exception))
        else:
            return True
        return False

    def _monitor(self):
        while True:
            for datapath in self.dpset.get_all():
                datapath = datapath[1]
                self._request_stats(datapath)
            hub.sleep(10)

    def _request_stats(self, datapath) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = parser.OFPMatch()
        req = parser.OFPFlowStatsRequest(datapath, 0,
                                         ofproto.OFPTT_ALL,
                                         ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                         cookie, cookie_mask,
                                         match)
        datapath.send_msg(req)
