from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import udp
from ryu.lib.packet import tcp


class Access_control(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        "This is counstructor"
        super(Access_control, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.IP_to_mac = {}
        print("First RYU APP")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        "To add the table flow miss entry"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        "This is to add/send flows to switch"
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # To change/modify the flow entries in the switch
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if priority == 0:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=10, hard_timeout=20,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    def allow_access(self, pkt, msg):
        "To allow Access for communication"
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        src = eth_packet.src
        dst = eth_packet.dst
        arp_packet = pkt.get_protocol(arp.arp)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)

        if ipv4_packet:
            source_ip = ipv4_packet.src
            destination_ip = ipv4_packet.dst
        elif arp_packet:
            source_ip = arp_packet.src_ip
            destination_ip = arp_packet.dst_ip

        self.IP_to_mac[source_ip] = src
        self.IP_to_mac[destination_ip] = dst

        print(self.IP_to_mac)

        in_port = msg.match['in_port']
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)

        datapath.send_msg(out)

    def deny_access(self, pkt, msg):
        "To deny access for communication"
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        arp_packet = pkt.get_protocol(arp.arp)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)

        source = arp_packet.src_ip
        dest = arp_packet.dst_ip
        src = eth_packet.src
        dst = eth_packet.dst

        self.IP_to_mac[source] = src
        print(self.IP_to_mac)
        in_port = msg.match['in_port']

        if dest in self.IP_to_mac.keys():
            match = parser.OFPMatch(eth_src=src, eth_dst=self.IP_to_mac[dest])
        else:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)

        mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                idle_timeout=10, hard_timeout=20,
                                match=match, instructions=[])

        datapath.send_msg(mod)

    def jparsing(self):
        import json

        global packet_restriction
        global group_restriction

        # data = '{"Policy": [{"group_isolation": "0", "UDP_packet_restriction": "0"}], "Groups": [{"1": {"host_ips": ["10.10.1.1", "10.10.1.2", "10.10.1.3"]}, "2": {"host_ips": ["10.10.1.4"]}}]}'
        f = open('Received.txt', 'r')
        data = f.read()
        f.close()

        parsed_json = json.loads(data)
        number_of_grps = len(parsed_json["Groups"][0])
        grp_name_list = parsed_json["Groups"][0].keys()
        group_restriction = int(parsed_json['Policy'][0]['group_isolation'])
        packet_restriction = int(parsed_json['Policy'][0]['UDP_packet_restriction'])
        master_ip_list = list()
        for grp in grp_name_list:
            unicode_ip_list = parsed_json["Groups"][0][grp]["host_ips"]
            ip_list = map(str, unicode_ip_list)
            master_ip_list.append(ip_list)

        print("master_IP_list", master_ip_list)

        return master_ip_list, grp_name_list

    def find_grp(self, master_ip_list, ip):
        for sublist in master_ip_list:
            # print("sublist", sublist)
            if ip in sublist:
                # print "Found it!", sublist
                break
        found_grp = master_ip_list.index(sublist)

        return found_grp

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        "When a packet_in message is received policy is enforced"
        print("Packet_In Message received")
        # packet_restriction = 1
        # group_restriction = 1
        # G1 = ["10.10.1.1", "10.10.1.2"]
        # G2 = ["10.10.1.3"]
        master_ip_list, grp_name_list = self.jparsing()


        msg = ev.msg

        pkt = packet.Packet(msg.data)
        arp_packet = pkt.get_protocols(arp.arp)
        ipv4_packet = pkt.get_protocols(ipv4.ipv4)
        udp_packet = pkt.get_protocols(udp.udp)

        if udp_packet:
            if packet_restriction == 1:
                print("UDP packet detected. Access Denied")
                return
            else:
                pass

        if arp_packet:
            print(arp_packet)
            source_ip = arp_packet[0].src_ip
            destination_ip = arp_packet[0].dst_ip
        elif ipv4_packet:
            source_ip = ipv4_packet[0].src
            destination_ip = ipv4_packet[0].dst

        src_g = str(grp_name_list[self.find_grp(master_ip_list, source_ip)])
        dest_g = str(grp_name_list[self.find_grp(master_ip_list, destination_ip)])


        # if source_ip in G1:
        #     src_g = 1
        # elif source_ip in G2:
        #     src_g = 2
        # else:
        #     src_g = 0
        #
        # if destination_ip in G1:
        #     dest_g = 1
        # elif destination_ip in G2:
        #     dest_g = 2
        # else:
        #     dest_g = 0

        if group_restriction == 1:
            if dest_g == src_g:
                print("Allow Packet Transfer")
                self.allow_access(pkt, msg)
            else:
                print("Deny the Access")
                self.deny_access(pkt, msg)
        else:
            print("Allow Access")
            self.allow_access(pkt, msg)
