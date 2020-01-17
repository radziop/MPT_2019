package pl.edu.agh.ddos;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
import net.floodlightcontroller.core.IOFSwitch;
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
	private int decrementTimer = 40000; //in milliseconds, time to decrement given flow's counter by 1;

	private Map<IPv4Address, Integer> counterMap;

	public PacketAnalyzer(Map<IPv4Address, Integer> counterMap) {
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

	public void decrementIPCounter(IPv4Address ip) {
		Timer timer = new Timer();
		timer.schedule(
			new java.util.TimerTask() {
				public void run(){
					if(counterMap.containsKey(ip) && counterMap.get(ip) > 0) {
						counterMap.put(ip, counterMap.get(ip) - 1);
						String logMessage = "Flow decremented: Source IP: " + ip.toString() + " Connections counter: "
								+ counterMap.get(ip).toString();
						logger.info("{}", logMessage);
					} else {
						counterMap.remove(ip);
						timer.cancel();
					}
				}
			}, decrementTimer, decrementTimer);

	}
	
	
	public void flowCounter() {

		if (dstIP.toString().equals("10.0.0.3") && flags == 2) { // if SYN flag set
			if (counterMap.containsKey(srcIP)) {
				counterMap.put(srcIP, counterMap.get(srcIP) + 1);
			} else {
				counterMap.put(srcIP, 1);
				decrementIPCounter(srcIP);
			}
			String logMessage = "New flow: Source IP: " + srcIP.toString() + " Connections counter: "
					+ counterMap.get(srcIP).toString();
			logger.info("{}", logMessage);
		}

	}

}
