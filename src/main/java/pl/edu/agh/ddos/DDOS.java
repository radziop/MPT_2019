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

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		PacketAnalyzer analyzer = new PacketAnalyzer(counterMap);
		analyzer.packetExtract(cntx);
		for(IPv4Address ip: counterMap.keySet()) {
			if(counterMap.get(ip) >= 20) {
				
		        Match.Builder mb = sw.getOFFactory().buildMatch();
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				mb.setExact(MatchField.IPV4_SRC, ip);
				Match m = mb.build();
				
		        OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		        List<OFAction> actions = new ArrayList<>();
		        
		        fmb.setHardTimeout(0)
		        .setIdleTimeout(120)
		        .setBufferId(OFBufferId.NO_BUFFER) 
		        .setMatch(m)
		        .setPriority(Integer.MAX_VALUE);
		        FlowModUtils.setActions(fmb, actions, sw);
		        sw.write(fmb.build());
			}
		}
		return Command.CONTINUE;
	}

}
