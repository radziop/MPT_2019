"""Topology
One switch, host acting as WWW server, one client host and one DoS attacker host :
 WWW --- switch --- host --- host
           --- attacker --- attacker --- attacker
                 
to run topology:
sudo mn --custom DDoS_mininet_topology.py --topo mytopo_dos          
"""
from mininet.topo import Topo

class MyTopo(Topo):
    #"Simple topology example."
    def __init__( elf):
        #"Create custom topo."
        # Initialize topology
        Topo.__init__( elf)
        # Add hosts and switches
        wwwServer = self.addHost('www')
        attackerHost1 = self.addHost('ah1')
        attackerHost2 = self.addHost('ah2')
        attackerHost3 = self.addHost('ah3')
        switch = self.addSwitch('s1')
        clientHost1 = self.addHost('ch')
        clientHost2 = self.addHost('ch2')
        # Add links
        self.addLink( wwwServer,switch)
        self.addLink( attackerHost1,switch)
        self.addLink( attackerHost2,switch)
        self.addLink( attackerHost3,switch)
        self.addLink( clientHost1,switch)
        self.addLink( clientHost2,switch)

topos = { 'mytopo_dos': ( lambda: MyTopo() ) }
