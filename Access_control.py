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

class Access_control(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
	def __init__(self, *args, **kwargs):
		"This is counstructor"
		super(Access_control, self).__init__(*args, **kwargs)
		print("First RYU APP for Internet Project")
	
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
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
					match=match, instructions=inst)
		datapath.send_msg(mod)
	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		"When a packet_in message is received policy is enforced"
		self.packet_restriction = 1
		self.group_restriction = 1
		G1 = ["10.10.1.1", "10.10.1.2"]
		G2 = ["10.10.1.3"]
		
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		pkt = packet.Packet(msg.data)
		eth_packet = pkt.get_protocols(ethernet.ethernet)
		print(eth_packet)
	
		ip_packet = pkt.get_protocols(ipv4.ipv4)
		print(ip_packet)

		tcp_packet = pkt.get_protocols(icmp.icmp)
		print(tcp_packet)
		
		# dst = ip_packet.dst
		# src = ip_packet.src
		
		
		
		
		
		
		
		

		
