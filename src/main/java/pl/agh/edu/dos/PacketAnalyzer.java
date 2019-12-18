package pl.agh.edu.dos;

import java.util.HashMap;
import java.util.Map;
import java.lang.Integer;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

public class PacketAnalyzer {

	private static final Logger logger = LoggerFactory.getLogger(PacketAnalyzer.class);
	private FloodlightContext cntx;
	private OFMessage msg;
	protected IFloodlightProviderService floodlightProvider;
	private Ethernet eth;
	private IPv4 ipv4;
	private TCP tcp;
	private UDP udp;
	private IPv4Address srcIP;
	private IPv4Address dstIP;
	private TransportPort srcPort;
	private TransportPort dstPort;
	
	
	private Map<String, Integer> counterMap;
	
	public PacketAnalyzer(Map<String, Integer> counterMap) {
		this.counterMap = counterMap;
	}

	public void packetExtract(FloodlightContext cntx) {
		this.cntx = cntx;
		extractEth();
	}

	public void extractEth() {
		eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (eth.getEtherType() == EthType.IPv4) {
			ipv4 = (IPv4) eth.getPayload();
			extractIp();
		}
	}

	public void extractIp() {
		if (ipv4.getProtocol() == IpProtocol.TCP) {
			srcIP = ipv4.getSourceAddress();
			dstIP = ipv4.getDestinationAddress();
			
			
			tcp = (TCP) ipv4.getPayload();
			extractTCP();
		}
	}

	public void extractTCP() {
		srcPort = tcp.getSourcePort();
		dstPort = tcp.getDestinationPort();
		
		flowCounter();
	}

	public void flowCounter() {
		//String logMessage ="New flow: src_ip: " + srcIP.toString() + ", src_TCP_port: " + srcPort.toString() +  ", dst_ip: " + dstIP.toString() + ", dst_TCP_port: " + dstPort.toString();
		//logger.info("{}", logMessage);
		
		if (dstIP.toString().equals("10.0.0.3")){
			if(counterMap.containsKey(srcIP.toString())) {
				counterMap.put(srcIP.toString(), counterMap.get(srcIP.toString())+1);
				}
			else {
				counterMap.put(srcIP.toString(), 1);
			}
			String logMessage = "New flow: Source IP: " + srcIP.toString() + " Connections counter: " + counterMap.get(srcIP.toString()).toString();
			logger.info("{}", logMessage);
		}
		
	}
	
	

}
