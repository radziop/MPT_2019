"""Topology
One switch, host acting as WWW server, one client host and one DoS attacker host :
 host --- switch --- host
                 --- host
"""
from mininet.topo import Topo

class MyTopo( Topo ):
    #"Simple topology example."
    def __init__( self ):
        #"Create custom topo."
        # Initialize topology
        Topo.__init__( self )
        # Add hosts and switches
        wwwServer = self.addHost( 'www' )
        attackerHost = self.addHost( 'ah' )
        switch = self.addSwitch( 's1' )
        clientHost = self.addHost( 'ch' )
        # Add links
        self.addLink( wwwServer, switch, bw = 10)
        self.addLink( attackerHost, switch )
        self.addLink( clientHost, switch )

topos = { 'mytopo': ( lambda: MyTopo() ) }
