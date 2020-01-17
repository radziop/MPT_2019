package pl.edu.agh.ddos;


import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.OFMessageUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DDOS implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	
	private Map<IPv4Address, Integer> counterMap = new HashMap<>();
	private int allIPTreshold = 500; //max counter for all flows at a time. When reached, the flow that has the largest counter is being dropped
	private int singleIPTreshold = 20; //max counter for given flow. When reached, the flow is being dropped 
	private int idle = 120; //in seconds, idleTimeout that will be set for flows destined to be dropped
	private int hard = 1200; //in seconds, hardTimeout that will be set for flows destined to be dropped
	@Override
	public String getName() {
		return DDOS.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(DDOS.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		logger.info("******************* DDoS Protection started **************************");
	}
	
	public void dropFlow(IPv4Address ip, IOFSwitch sw, String cause) {
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		mb.setExact(MatchField.IPV4_SRC, ip);
		Match m = mb.build();
		
        OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
        List<OFAction> actions = new ArrayList<>();
        
        fmb.setHardTimeout(hard)
        .setIdleTimeout(idle)
        .setBufferId(OFBufferId.NO_BUFFER) 
        .setMatch(m)
        .setPriority(Integer.MAX_VALUE);
        FlowModUtils.setActions(fmb, actions, sw);
        sw.write(fmb.build());
        
        String logMessage = "Dropping flow: Source IP: " + ip.toString() + " Connections counter: "
				+ counterMap.get(ip).toString() + " Cause: " + cause;
		logger.info("{}", logMessage);
		
		counterMap.remove(ip);
		
	}
	
	public int sumCounter() {
		int sum = 0;
		for(int counter: counterMap.values()) {
			sum += counter;
		}
		return sum;
	}
	
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		PacketAnalyzer analyzer = new PacketAnalyzer(counterMap);
		analyzer.packetExtract(cntx);
		
		for(IPv4Address ip: counterMap.keySet()) { //drop all flows that have big enough connection's counter
			if(counterMap.get(ip) >= singleIPTreshold) {
				dropFlow(ip, sw, "Too many simultaneous connections");
			}
		}
		
		while(sumCounter() >= allIPTreshold) { //if sum of connections from all sources is big enough, drop the largest flow and repeat
			IPv4Address ipOfMaxCounter = counterMap.entrySet().stream().max((ip1, ip2) -> ip1.getValue() > ip2.getValue() ? 1 : -1).get().getKey();
			dropFlow(ipOfMaxCounter, sw, "Maximum connections number reached while this flow has largest connection counter");
		}
		return Command.CONTINUE;
	}

}
