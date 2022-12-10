
# SDN Firewall Implementaion and Deep packet inspection

The breakthrough networking architecture known as Software Defined Network (SDN) separates the network control plane from the data plane and assigns control of the network to a controller running at the control layer.
SDN presents a chance to alter the limits of existing network infrastructures by allowing networks to be fully controlled by software applications.
SDN has drastically altered network architecture since its inception, which has made network control easier, but on the other hand, several issues have emerged.
The security threats are one of the key issues made apparent by the new SDN architecture.
Using network firewalls to enforce security policies, traffic can be made secure. 

## Overview of SDN FW Implementaion

The OpenFlow switch's acts as the "brain" for learning new switches.
When a packet is seen, we want to output it on a port that will lead to the final destination ultimately.
To achieve this, we create a table that links ports to addresses. We fill the table with data by tracking traffic.
When a packet is visible we know that source is out because it comes from some port.
We check up the destination in our database when we want to forward traffic table.
If we are unsure of the port, we just send the message all ports other from the one it entered through. Our implementation is based on the Pox L-2 Learning Switch.


## Firewall Algorithm

Before understanding the algorithm, we need to understand the type of topology we are dealing with.
Each and every host is connected to the common switch which uses Open Flow protocol and that switch is in turn connected to the Pox controller. 

Every packet that is passing through our network will go through the switch. And for every packet, the switch will send it to the controller. The controller in the end makes the decision to either allow the packet or to drop the packet based on the rules. 

For demonstration purposes we have written two rules for Level 2 and Level 3 firewall. Before running our topology we need to make sure the Pox controller is running with the given rules. Once Pox controller is set up, we can start our mininet topology.

Once the system is set up and we start pinging the hosts or when packet transfer starts happening: \
**Step 1**: The packet goes to the switch. \
**Step 2**: The switch sends it to the controller. \
**Step 3**: The controller compares the packet details such as SRC, DST, PORT, etc. to the Firewall Rules. \
**Step 4**: If the controller detects that a rule has been written for this packet then the controller drops the packet. \
**Step 5**: If not, then the controller sends it back to the Switch. The switch does not know "who" the DST is, so it floods the packet and slowly it builds the routing table. \


## Code Organization

The `topology.py` conatins the mininet Script which creates the topology for a simple test network.
`Firewall_controller.py` 


## Deployment
Required Dependencies: Pox framework and Mininet.

To install Mininet: 
```bash
sudo apt-get upgrade
sudo apt-get update
sudo apt-get install mininet
```

To install Pox:
```bash
git clone http://github.com/noxrepo/pox
cd pox
```

Once you are in the pox folder: 
```bash
  ./pox.py <firewall>
```

Then once your controller is running, we can start the mininet topology:

```bash
  sudo python <topology.py>
```

Then you can test your system using Mininet commands like:
```bash
h1 ping h2
h2 ping h3
h1 wget 127.0.0.3
```

## Deep Packet Inspection

Deep packet inspection (DPI) is a type of data processing that inspects in detail the data being sent over a computer network, and may take actions such as alerting, blocking, re-routing, or logging it accordingly. Deep packet inspection is often used to baseline application behavior, analyze network usage, troubleshoot network performance, ensure that data is in the correct format, check for malicious code, eavesdropping, and internet censorship.

### wireshark implementation and analysis of packets

In our project we have implemented packet caputure analysis from capture files obtained from MACCDC.Our analysis included wireshark capture of 8.6 million packets and histogram analysis for anaomoly detection and protocol hierarchy statistics to verify any anomaly in TCP, HTTP or any file transfer protocols.
Our results included examining for natural deviations from the rule of thumb, and concluding with no intrusion or anomoly detection for the capture packet, with expected protocols detected.

## Packet Statistics

`TCP - 98.2 %
HTTP - 1.8%`

## Contributers

- [@saiabhishek28](https://www.github.com/saiabhishek28)
- [@Aadithya-Srinivasan-Anand](https://github.com/Aadithya-Srinivasan-Anand)
- Professor Jose Santos (Instructor)


