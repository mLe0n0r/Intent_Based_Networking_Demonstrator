from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

"""
The controller must:

1) Learn about the network
   - Determine from which port each host enters the switch
   - Discover where each destination host is located
   - Use this information to forward packets correctly

2) Apply intents
   - Allow communication between selected hosts
   - Block or isolate specific hosts
   - Optionally prioritize certain traffic flows

3) Install rules
   - Forwarding rules for allowed traffic
   - Drop rules for blocked traffic
   - Priority rules for high-priority flows
"""

class IntentController(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION] # OpenFlow version the controller is going to use

    def __init__(self, *args, **kwargs):
        super(IntentController, self).__init__(*args, **kwargs)
        self.mac_and_port = {} # empty dictionary

        self.allowed_pairs = [ # h1 <-> h2
            ("10.0.0.1", "10.0.0.2"),
            ("10.0.0.2", "10.0.0.1")
        ]

    def allowed_communication(self, src_ip, dst_ip):
        """
        Returns true is the pair matches the defined allowed pair
        """

        return (src_ip, dst_ip) in self.allowed_pairs

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

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # event handler
    # def packet_in_handler(self, ev):
    #     msg = ev.msg # OpenFlow that came from the switch
    #     dp = msg.datapath
    #     parser = dp.ofproto_parser # to send OpenFlow rule
    #     ofp = dp.ofproto # OpenFlow constants

    #     dpid = dp.id
    #     in_port = msg.match["in_port"]

    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocol(ethernet.ethernet)
    #     ip_pkt = pkt.get_protocol(ipv4.ipv4)

    #     src_mac = eth.src
    #     dst_mac = eth.dst

    #     self.learn_mac(dpid, src_mac, in_port)

         


