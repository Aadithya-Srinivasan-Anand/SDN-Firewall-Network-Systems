
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
If we are unsure of the port, we just send the message all ports other from the one it entered through.

Our algorithm, in brief, looks like this: 

Step 1: For each packet that we get from the switch
- Use the source address and switch port to update the port table

.... End of step 1.....

Step 2: Drop packet if link-local traffic ( packets destination is a bridge filtered address)

.... End of Step 2.....

Step 3: Is destination multicast?
     Yes: Flood the packet

.... End of Step 3.....

Step 4: Port for destination address in our address/port table?
     No: Flood the packet

.... End of Step 4.....

Step 5: Is output port the same as input port?
     Yes: Drop packet and similar ones for a while

.... End of Step 5.....

Step 6: Install flow table entry in the switch so that this
     flow goes out the appopriate port
     Send the packet out appropriate port

.... End of Step 6.....

## Code organisation

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


## Contributers

- [@saiabhishek28](https://www.github.com/saiabhishek28)
- [@Aadithya-Srinivasan-Anand](https://github.com/Aadithya-Srinivasan-Anand)
- Professor Jose Santos (Instructor)


