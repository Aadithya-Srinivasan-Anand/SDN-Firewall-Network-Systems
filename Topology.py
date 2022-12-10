"""
Firewall based SDN network
"""
from mininet.Topo import Topology
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI

class Topo_Single_Switchy(Topology):
    "Single switch connected to n hosts."
    def build(self, n=2):
        switch = self.addSwitch('s1', dpid="00000000000007")
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1), ip='10.0.0.%s' % (h+1), mac='00:00:00:00:00:0%s' % (h+1))
            self.addLink(host, switch)

def simpleTest():
    "Create and test a simple network"
    Topology = Topo_Single_Switchy(n=4)
    net = Mininet(Topology, controller=None)
    " Remote POX Controller"
    c = RemoteController('c', '0.0.0.0', 6633)
    net.addController(c)
    net.start()
    print ("Dumping host connections")
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
