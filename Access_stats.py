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
from ryu.lib import hub

class Access_control(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """This is constructor"""
        super(Access_control, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.IP_to_mac = {}
        self.datapaths = {}
        self.monitoring = hub.spawn(self.collect_stats)
        print("First RYU APP")


    def collect_stats(self):
        """This is to collect stats from the network after every 10 seconds"""
        while True:
            for dp in self.datapaths.values():
                print("Sending stat request")
                self.send_request(dp)
            hub.sleep(10)

    def send_request(self, datapath):
        """This is to request stats from the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # match = parser.OFPMatch(ipv4_src = '10.10.1.1', ipv4_dst = '10.10.1.3')
        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_parser(self, ev):
        body = str(ev.msg.body)
        op = open('stats.log', 'w')
        op.write(body)
        op.close()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """To add the table flow miss entry"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        """"This is to add/send flows to switch"""
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
        """To allow Access for communication"""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.IP_to_mac.setdefault(dpid, {})
        # print(self.mac_to_port)
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

        self.IP_to_mac[dpid][source_ip] = src
        self.IP_to_mac[dpid][destination_ip] = dst

        # print(self.IP_to_mac)

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
        """To deny access for communication"""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.IP_to_mac.setdefault(dpid, {})

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        arp_packet = pkt.get_protocol(arp.arp)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)

        if arp_packet:
            source = arp_packet.src_ip
            dest = arp_packet.dst_ip
        elif ipv4_packet:
            source = ipv4_packet.src
            dest = ipv4_packet.dst

        src = eth_packet.src
        dst = eth_packet.dst

        self.IP_to_mac[dpid][source] = src
        # print(self.IP_to_mac)
        in_port = msg.match['in_port']

        if dest in self.IP_to_mac[dpid].keys():
            match = parser.OFPMatch(eth_src=src, eth_dst=self.IP_to_mac[dpid][dest])
        else:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)

        mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                idle_timeout=10, hard_timeout=20,
                                match=match, instructions=[])

        datapath.send_msg(mod)

    def jparsing(self):
        """"This is to parse JSON data received from Policy Manager"""
        import json

        global packet_restriction
        global group_restriction

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

        # print("master_IP_list", master_ip_list)

        return master_ip_list, grp_name_list

    def find_grp(self, master_ip_list, ip):
        """This is to find the group index of the given IP"""
        flag = 0
        for sublist in master_ip_list:
            # print("sublist", sublist)
            if ip in sublist:
                # print "Found it!", sublist
                #found_grp = master_ip_list.index(sublist)
                flag = 1
                break
        if flag ==1:
            found_grp =  master_ip_list.index(sublist)
            return found_grp
        else:
            return None

        # found_grp = master_ip_list.index(sublist)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """"When a packet_in message is received policy is enforced"""
        print("Packet_In Message received")
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
           # print(arp_packet)
            source_ip = arp_packet[0].src_ip
            destination_ip = arp_packet[0].dst_ip
        elif ipv4_packet:
            source_ip = ipv4_packet[0].src
            destination_ip = ipv4_packet[0].dst

        # print("Source IP: ", source_ip)
        # print("Destination IP: ", destination_ip)

        index = self.find_grp(master_ip_list, source_ip)
        # print(index)
        if index is not None:
            src_g = str(grp_name_list[index])
            print("IP: {}, Group: {}".format(source_ip, src_g))
        else:
            print("IP: {} not found in the list. Access Denied".format(source_ip))
            return

        index = self.find_grp(master_ip_list, destination_ip)
        # print(index)
        if index is not None:
            dest_g = str(grp_name_list[index])
            print("IP: {} , Group: {}".format(destination_ip, dest_g))
        else:
            print("IP: {} not found in the list. Access Denied".format(destination_ip))
            return


        if group_restriction == 1:
            if dest_g == src_g:
                print("Allow Packet Transfer")
                self.allow_access(pkt, msg)
            else:
                print("Deny the Access. Group Mismatch")
                self.deny_access(pkt, msg)
        else:
            print("Allow Access")
            self.allow_access(pkt, msg)

