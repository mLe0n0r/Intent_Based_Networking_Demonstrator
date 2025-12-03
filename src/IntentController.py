from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib.packet import arp


# The controller must:

# 1) Learn about the network
#    - Determine from which port each host enters the switch
#    - Discover where each destination host is located
#    - Use this information to forward packets correctly

# 2) Apply intents
#    - Allow communication between selected hosts
#    - Block or isolate specific hosts
#    - Optionally prioritize certain traffic flows

# 3) Install rules
#    - Forwarding rules for allowed traffic
#    - Drop rules for blocked traffic
#    - Priority rules for high-priority flows


class IntentController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # OpenFlow version the controller is going to use

    def __init__(self, *args, **kwargs):
        super(IntentController, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # empty dictionary

        self.BLOCK_PRIORITY = 20 # in doubt is better to block
        self.NORMAL_PRIORITY = 10

        self.allowed_pairs = [ # 1) h1 <-> h2
            ("10.0.0.1", "10.0.0.2"),
            ("10.0.0.2", "10.0.0.1")
        ]

    def learn_mac(self, dpid, src_mac, in_port):
        """
        Stores the MAC address of each host and the corresponding switch port.

        Arguments:
        dpid: switch identifier
        src_mac: Mac address of destination
        in_port: switch port from where the packet arrived
        """

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

    def get_out_port(self, dpid, dst_mac, dp):
        """
        Decides from which port the packet should leave the switch
        
        Arguments:
        dpid: switch identifier
        dst_mac: Mac address of destination
        dp: datapath (represents the switch)
        """

        if dst_mac in self.mac_to_port.get(dpid, {}):
            return self.mac_to_port[dpid][dst_mac] # if it had already learnt the destination's mac port
        return dp.ofproto.OFPP_FLOOD # else flood (sents to every port excluding the one from where it arrived)

    def send_packet(self, dp, msg, in_port, actions):
        """
        Sends the packet back to the switch with instructions

        Arguments:
        dp: datapath
        msg: original OpenFlow message sent by the switch
        in_port: switch port from where the packet arrived
        actions: list of action that should be applied to the packet
        """
    
        parser = dp.ofproto_parser # to send OpenFlow rule
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # first configuration
    def switch_features_handler(self, ev):
        """
        Installs the initial rule in the switch (table-miss)
        
        Argument:
        ev: event that contains the OpenFlow message sent by the switch
        """

        dp = ev.msg.datapath
        parser = dp.ofproto.ofproto_parser

        match = parser.OFPMatch() # can consider anything
        actions = [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER, dp.ofproto.OFPCML_NO_BUFFER)] # any packet is going to be sent to the controller
        inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst) # FlowMod message
        dp.send_msg(mod)

    def add_flow(self, dp, priority, match, actions):
        """
        Creates a flow entry in the switch's table

        Arguments:
        dp: datapath
        priority
        match: what the switch must recognise
        actions: what the switch must do
        """

        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flowMod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(flowMod)

    # =================
    #    Main Logic:
    # =================
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # event handler
    def packet_in_handler(self, ev):
        msg = ev.msg # OpenFlo message that came from the switch
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto 

        dpid = dp.id
        in_port = msg.match["in_port"]

        # parse packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        self.learn_mac(dpid, eth.src, in_port)

        # Handle ARP packets separately to avoid accidental drops:
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            out_port = self.get_out_port(dpid, eth.dst, dp)
            actions = [parser.OFPActionOutput(out_port)]

            match = parser.OFPMatch(eth_type=0x0806, arp_spa=arp_pkt.src_ip, arp_tpa=arp_pkt.dst_ip)
            self.add_flow(dp, self.NORMAL_PRIORITY, match, actions)

            self.send_packet(dp, msg, in_port, actions)
            return

        # Handle non-ipv4 packets: (flood)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None: 
            action = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            self.send_packet(dp, msg, in_port, action)
            return
        
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        
        # 1) Allow only communication between two specific hosts
        if (src_ip, dst_ip) not in self.allowed_pairs: # -> block
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            self.add_flow(dp, self.BLOCK_PRIORITY, match, [])
            return 
            
        out_port = self.get_out_port(dpid, eth.dst, dp)
        actions = [parser.OFPActionOutput(out_port)] # send packet from the port out_port
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip) # aply the action to the respective packets

        self.add_flow(dp, self.NORMAL_PRIORITY, match, actions)
        self.send_packet(dp, msg, in_port, actions)
        
        



        


         


