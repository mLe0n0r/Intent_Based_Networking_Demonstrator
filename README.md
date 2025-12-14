# Intent Based Networking Demonstrator
This project implements an Intent-Based Networking (IBN) demonstrator using Software-Defined Networking (SDN) principles.
The system is built with Ryu (OpenFlow 1.3) and Mininet, and showcases how high-level network intents can be dynamically enforced by a centralized controller.

## Implemented Intents
1) **Limited Communication:** Allows communication only between specific host pairs. All other traffic is automatically blocked.

2) **HTTP Priority:** Detects HTTP traffic (TCP port 80) and installs higher-priority forwarding rules for it.

3) **Limited Bandwidth:** Limits the bandwidth between two specific hosts using OpenFlow meters.

4) **Scan Detection:** Detects hosts that contact too many distinct destinations in a short period of time and temporarily blocks them.

## Topologies



## ▶️ How to run
Start the Controller:
```
>> cd src
>> ryu-manager IntentController.py
```

Start Mininet:
```
>> cd src
>> sudo mn --custom MyTopology.py --topo myTopo --controller=remote,ip=127.0.0.1 --switch ovs,protocols=OpenFlow13
```

### Credits
Leonor Guedes