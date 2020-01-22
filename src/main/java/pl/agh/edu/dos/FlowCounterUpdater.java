package pl.agh.edu.dos;

import java.util.Map;
import java.lang.Integer;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

public class FlowCounterUpdater {

	private static final Logger logger = LoggerFactory.getLogger(FlowCounterUpdater.class);
	private FloodlightContext floodlightContext;
	private Ethernet frame;
	private IPv4 ipv4Address;
	private TCP tcpPayload;
	private IPv4Address sourceAddress;
	private IPv4Address destinationAddress;
	private short tcpFlags;

	private Map<IPv4Address, Integer> counterMap;

	public FlowCounterUpdater(Map<IPv4Address, Integer> counterMap) {
		this.counterMap = counterMap;
	}

	public void analyzePacket(FloodlightContext cntx) {
		this.floodlightContext = cntx;
		
		frame = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (frame.getEtherType() == EthType.IPv4) {
			ipv4Address = (IPv4) frame.getPayload();
			getIpAddressFromPacket();
		}
	}

	public void getIpAddressFromPacket() {
		if (ipv4Address.getProtocol() == IpProtocol.TCP) {
			sourceAddress = ipv4Address.getSourceAddress();
			destinationAddress = ipv4Address.getDestinationAddress();
			tcpPayload = (TCP) ipv4Address.getPayload();
			
			extractTcpDataFromPacket();
		}
	}

	public void extractTcpDataFromPacket() {
		tcpFlags = tcpPayload.getFlags();
		updateCounter();
	}

	public void updateCounter() {
		// String logMessage ="New flow: src_ip: " + srcIP.toString() + ", src_TCP_port:
		// " + srcPort.toString() + ", dst_ip: " + destinationAddress.toString() + ", dst_TCP_port: "
		// + dstPort.toString();
		// logger.info("{}", logMessage);

		if (destinationAddress.toString().equals("10.0.0.3") && tcpFlags == 2) { // if SYN flag set
			if (counterMap.containsKey(sourceAddress)) {
				counterMap.put(sourceAddress, counterMap.get(sourceAddress) + 1);
			} else {
				counterMap.put(sourceAddress, 1);
			}
			String logMessage = "New flow from Source IP: " + sourceAddress.toString() + " received. Current connection counter: "
					+ counterMap.get(sourceAddress).toString();
			logger.info("{}", logMessage);
			
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
		if (counterMap.containsKey(sourceAddress) && counterMap.get(sourceAddress) > 0) {
			counterMap.put(sourceAddress, counterMap.get(sourceAddress) - 1);
		}
		String logMessage = "Flow counter updated for Source IP: " + sourceAddress.toString() + "; Current connection counter: "
				+ counterMap.get(sourceAddress).toString();
		logger.info("{}", logMessage);
	}
	
}
