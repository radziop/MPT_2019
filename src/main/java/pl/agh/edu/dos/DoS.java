package pl.agh.edu.dos;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.action.OFAction;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.util.FlowModUtils;

public class DoS implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	
	private Map<IPv4Address, Integer> counterMap = new HashMap<>();
	private Integer simultaneousConnectionThreshold = 15;
	private Integer blockingTime = 30;
	private List<IPv4Address> blocked_hosts = new ArrayList<>();

	
	@Override
	public String getName() {
		return DoS.class.getSimpleName();
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
		logger = LoggerFactory.getLogger(DoS.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		logger.info("### DoS Protection active ###");
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext floodlightContext) {
//		logger.info("******************* New Packet ***************************************");
		
		FlowCounterUpdater counterUpdater = new FlowCounterUpdater(counterMap);
		counterUpdater.analyzePacket(floodlightContext);
		
		for(IPv4Address ip: counterMap.keySet()) {
			if (counterMap.get(ip) > simultaneousConnectionThreshold) {
				if (!blocked_hosts.contains(ip)){
					blockHostByIpAddress(sw, ip);
				}
			}
		}
		
		return Command.CONTINUE;
	}

	public void blockHostByIpAddress(final IOFSwitch sw, final IPv4Address ip_address) {
        Match.Builder mb = sw.getOFFactory().buildMatch();
			mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			mb.setExact(MatchField.IPV4_SRC, ip_address);
			final Match flow_match = mb.build();

        OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
        List<OFAction> actions = new ArrayList<>();

        fmb.setHardTimeout(0)
        .setIdleTimeout(120)
        .setBufferId(OFBufferId.NO_BUFFER) 
        .setMatch(flow_match)
        .setPriority(Integer.MAX_VALUE);
        FlowModUtils.setActions(fmb, actions, sw);
        sw.write(fmb.build());
		
        blocked_hosts.add(ip_address);
		String logMessage = "Host with source IP: " + ip_address.toString() + " blocked for " + blockingTime + " seconds!";
		logger.info("{}", logMessage);
		
		// Schedule unblocking the host after 'blockingTime' timer expires
		new java.util.Timer().schedule(new java.util.TimerTask() {
			@Override
		    public void run() {unblockHostByIpAddress(sw, flow_match, ip_address);}
		}, blockingTime*1000);
	}
	
	public void unblockHostByIpAddress(IOFSwitch sw, Match flow_match, IPv4Address ip_address) {
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowDelete();
        fmb.setHardTimeout(0)
        .setIdleTimeout(120)
        .setBufferId(OFBufferId.NO_BUFFER) 
        .setMatch(flow_match)
        .setPriority(Integer.MAX_VALUE);
        sw.write(fmb.build());
		
		blocked_hosts.remove(ip_address);
		String logMessage = "Host with source IP: " + ip_address.toString() + " unblocked.";
		logger.info("{}", logMessage);
	}
	
}
