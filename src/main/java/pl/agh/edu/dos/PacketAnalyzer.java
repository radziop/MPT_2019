package pl.agh.edu.dos;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.lang.Integer;
import java.util.Timer;
import java.util.TimerTask;

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
	private Integer simultaneousConnectionThreshold;
	private Integer blockingTime;

	public PacketAnalyzer(Map<String, Integer> counterMap, Integer simultaneousConnectionThreshold, Integer blockingTime) {
		this.counterMap = counterMap;
		this.simultaneousConnectionThreshold = simultaneousConnectionThreshold;
		this.blockingTime = blockingTime;
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
		// String logMessage ="New flow: src_ip: " + srcIP.toString() + ", src_TCP_port:
		// " + srcPort.toString() + ", dst_ip: " + dstIP.toString() + ", dst_TCP_port: "
		// + dstPort.toString();
		// logger.info("{}", logMessage);

		if (dstIP.toString().equals("10.0.0.3") && flags == 2) { // if SYN flag set
			if (counterMap.containsKey(srcIP.toString())) {
				counterMap.put(srcIP.toString(), counterMap.get(srcIP.toString()) + 1);
			} else {
				counterMap.put(srcIP.toString(), 1);
			}
			String logMessage = "New flow: Source IP: " + srcIP.toString() + "; Connection counter: "
					+ counterMap.get(srcIP.toString()).toString();
			logger.info("{}", logMessage);
			if (counterMap.get(srcIP.toString()) > simultaneousConnectionThreshold) {
				blockHostByIpAddress();
			}
			scheduleCounterDecrementation(10000);
		}

	}
	
	public void scheduleCounterDecrementation(Integer timer) {
		new java.util.Timer().schedule( 
		        new java.util.TimerTask() {
		            @Override
		            public void run() {
		                decrementFlowCounter();
		            }
		        }, 
		        timer 
		);
	}

	public void decrementFlowCounter() {
		if (counterMap.containsKey(srcIP.toString()) && counterMap.get(srcIP.toString()) > 0) {
			counterMap.put(srcIP.toString(), counterMap.get(srcIP.toString()) - 1);
		}
		String logMessage = "Counter updated for flow with Source IP: " + srcIP.toString() + "; Current connection counter: "
				+ counterMap.get(srcIP.toString()).toString();
		logger.info("{}", logMessage);
	}
	
	public void blockHostByIpAddress() {
		String command = "ovs-ofctl add-flow s1 \"nw_src=" + srcIP + "\",actions=drop";
		// TODO send rest command
		
		String logMessage = "Host with source IP: " + srcIP.toString() + " blocked for " + blockingTime + " seconds!";
		logger.info("{}", logMessage);
		
		// Schedule unblocking the host after 'blockingTime' timer expires
		new java.util.Timer().schedule(new java.util.TimerTask() {
			@Override
		    public void run() {unblockHostByIpAddress();}
		}, blockingTime*1000);
	}
	
	public void unblockHostByIpAddress() {
		String command = "ovs-ofctl del-flows s1 \"nw_src=" + srcIP + "\"";
		// TODO send rest command
		
		String logMessage = "Host with source IP: " + srcIP.toString() + " unblocked.";
		logger.info("{}", logMessage);
	}
}
