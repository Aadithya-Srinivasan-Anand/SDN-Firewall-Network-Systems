"""
A Firewall based SDN Controller
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.addresses import IPAddr, EthAddr
import time

log = core.getLogger()

_flood_delay = 0 # Delay immediate flooding when connecting is made

class LearningSwitch (object): 
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    self.macTopologyrt = {} # Table gen

    self.firewall = {} # firewall gen - dictonary format

    self.Implement_FW_rule(dpid_to_str(connection.dpid), 0, IPAddr('10.0.0.1'), IPAddr('10.0.0.4'),0) # rule entries

    connection.addListeners(self) # listening to upcomming packets

    self.hold_down_expired = _flood_delay == 0

  def Implement_FW_rule (self, dpidstr, macstr, srcipstr, dstipstr, dstport,value=True): # adding rules
      if srcipstr == 0 and dstipstr == 0:
        self.firewall[(dpidstr,macstr)] = True
        log.debug("Adding L2-firewall rule of Src(%s) in %s", macstr, dpidstr)
      elif dstport == 0:
        self.firewall[(dpidstr,srcipstr,dstipstr)] = True
        log.debug("Adding L3-firewall rule of %s -> %s in %s", srcipstr, dstipstr, dpidstr)
      elif srcipstr == 0:
        self.firewall[(dpidstr,dstipstr,dstport)] = True
        log.debug("Adding L4-firewall rule of Dst(%s,%s) in %s", dstipstr, dstport, dpidstr)
      else:
        self.firewall[(dpidstr,srcipstr,dstipstr,dstport)] = True
        log.debug("Adding firewall rule of %s -> %s,%s in %s", srcipstr, dstipstr, dstport, dpidstr)

  def Rule_deletion (self, dpidstr, macstr, srcipstr, dstipstr, dstport): # rule deletion
     try:
       if srcipstr == 0 and dstipstr == 0:
         del self.firewall[(dpidstr,macstr)]
         log.debug("Deleting L2-firewall rule of Src(%s) in %s", macstr, dpidstr)
       elif dstport == 0:
         del self.firewall[(dpidstr,srcipstr,dstipstr)]
         log.debug("Deleting L3-firewall rule of %s -> %s in %s", srcipstr, dstipstr, dpidstr)
       elif srcipstr == 0:
         del self.firewall[(dpidstr,dstipstr,dstport)]
         log.debug("Deleting L4-firewall rule of Dst(%s,%s) in %s", dstipstr, dstport, dpidstr)
       else:
         del self.firewall[(dpidstr,srcipstr,dstipstr,dstport)]
         log.debug("Deleting firewall rule of %s -> %s,%s in %s", srcipstr, dstipstr, dstport, dpidstr)
     except KeyError:
       log.error("Cannot find Rule %s(%s) -> %s,%s in %s", srcipstr, macstr, dstipstr, dstport, dpidstr)

  
  def Rule_Checker (self, dpidstr, macstr, srcipstr, dstipstr, dstport): # checking compliance
    # Source Link blocked
    try:
      entry = self.firewall[(dpidstr, macstr)]
      log.info("L2-Rule Src(%s) found in %s: DROP", macstr, dpidstr)
      return entry
    except KeyError:
      log.debug("Rule Src(%s) NOT found in %s: L2-Rule NOT found", macstr, dpidstr)

    try:
      entry = self.firewall[(dpidstr, srcipstr, dstipstr)] # blocking H-H
      log.info("L3-Rule (%s x->x %s) found in %s: DROP", srcipstr, dstipstr, dpidstr)
      return entry
    except KeyError:
      log.debug("Rule (%s -> %s) NOT found in %s: L3-Rule NOT found", srcipstr, dstipstr, dpidstr)
      
    try:
      entry = self.firewall[(dpidstr, dstipstr, dstport)]
      log.info("L4-Rule Dst(%s,%s)) found in %s: DROP", dstipstr, dstport, dpidstr)
      return entry
    except KeyError:
      log.debug("Rule Dst(%s,%s) NOT found in %s: L4-Rule NOT found", dstipstr, dstport, dpidstr)
      return False

  def _handle_PacketIn (self, event): # alg implementaion
    packet = event.parsed
    inport = event.port

    def flood (message = None):
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay: # flood only is time>= req.

        if self.hold_down_expired is False:
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding", dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None): # to drop packets with conditional check met
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_flow_mod() #creats a flow modification message
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.match.dl_dst = None
        msg.idle_timeout = 120
        msg.hard_timeout = 120
        msg.priority = 65535 #priority at which a rule will match, higher is better.
        msg.command = of.OFPFC_MODIFY
        msg.flags = of.OFPFF_CHECK_OVERLAP
        msg.data = event.ofp
        self.connection.send(msg)# send the message to the OpenFlow switch

    self.macTopologyrt[packet.src] = event.port 
    dpidstr = dpid_to_str(event.connection.dpid) # DPID of the connecting switch
    if isinstance(packet.next, ipv4):
      log.debug("%i IP %s => %s", inport, packet.next.srcip,packet.next.dstip)
      segmant = packet.find('tcp')
      if segmant is not None:
        # Check the Firewall Rules in MAC, IPv4 and TCP Layer
        if self.Rule_Checker(dpidstr, packet.src, packet.next.srcip, packet.next.dstip, segmant.dstport) == True:
          drop()
          return
      else:
        if self.Rule_Checker(dpidstr, packet.src, packet.next.srcip, packet.next.dstip, 0) == True:  # Check the Firewall Rules in MAC and IPv4 Layer
          drop()
          return
    elif isinstance(packet.next, arp):
      if self.Rule_Checker(dpidstr, packet.src, 0, 0, 0) == True: # Check the Firewall Rules in MAC Layer
        drop()
        return
      a = packet.next
      log.debug("%i ARP %s %s => %s", inport, {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
    elif isinstance(packet.next, ipv6): #only ipv4 packets are handeled 
      return

    if not self.transparent: 
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() 
        return

    if packet.dst.is_multicast:
      flood() 
    else:
      if packet.dst not in self.macTopologyrt: 
        flood("Port for %s unknown -- flooding" % (packet.dst,)) 
      else:
        port = self.macTopologyrt[packet.dst]
        if port == event.port
          
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop." % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        self.connection.send(msg)

class l2_learning (object): # once conneted - switch to learning switches
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay): # Launch the learning switch
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))
