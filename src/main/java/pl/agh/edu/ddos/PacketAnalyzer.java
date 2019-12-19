package pl.agh.edu.dos;

import java.util.HashMap;
import java.util.List;
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
	private short flags;

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
		flags = tcp.getFlags();
		flowCounter();
	}

	public void flowCounter() {

		if (dstIP.toString().equals("10.0.0.3") && flags == 2) { // if SYN flag set
			if (counterMap.containsKey(srcIP.toString()+":"+srcPort.toString())) {
				counterMap.put(srcIP.toString()+":"+srcPort.toString(), counterMap.get(srcIP.toString()+":"+srcPort.toString()) + 1);
			} else {
				counterMap.put(srcIP.toString()+":"+srcPort.toString(), 1);
			}
			String logMessage = "New flow: Source IP/Port: " + srcIP.toString()+":"+srcPort.toString() + " Connections counter: "
					+ counterMap.get(srcIP.toString()+":"+srcPort.toString()).toString();
			logger.info("{}", logMessage);
		}

	}

}
