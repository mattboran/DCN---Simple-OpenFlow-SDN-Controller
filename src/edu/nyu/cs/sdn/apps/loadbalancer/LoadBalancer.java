package edu.nyu.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import com.sun.java.util.jar.pack.Instruction.Switch;

import edu.nyu.cs.sdn.apps.sps.InterfaceShortestPathSwitching;
import edu.nyu.cs.sdn.apps.sps.ShortestPathSwitching;
import edu.nyu.cs.sdn.apps.util.ArpServer;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
    public static final short PRIORITY_LOW = 1;
    public static final short PRIORITY_MED = 2;
    public static final short PRIORITY_HI = 3;

	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private InterfaceShortestPathSwitching shortestPathSwitchingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.shortestPathSwitchingApp = context.getServiceImpl(InterfaceShortestPathSwitching.class);
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
	}
	
	/***
	 * Add rules for ARP on switch at switchId
	 * @param switchId = long ID of switch
	 * @return true if success, else false
	 */
	private boolean addRulesForARP(long switchId)
	{
		Collection<LoadBalancerInstance> loadBalancerList = this.instances.values();
		// Iterate through each LB
		for (LoadBalancerInstance lb : loadBalancerList)
		{
			OFMatch match = new OFMatch();
			List<OFMatchField> matchFields = new ArrayList<OFMatchField>();
    		OFMatchField field1 = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_ARP);
    		OFMatchField field2 = new OFMatchField(OFOXMFieldType.IPV4_DST, lb.getVirtualIP());
    		
    		matchFields.add(field1);
    		matchFields.add(field2);
    		
    		match.setMatchFields(matchFields);
    		
    		OFAction action = new OFActionOutput(OFPort.OFPP_CONTROLLER);
    		OFInstruction instruction = new OFInstructionApplyActions(Arrays.asList(action));
    		if(false == SwitchCommands.installRule(this.floodlightProv.getSwitch(switchId), this.table,
    				PRIORITY_MED, match, Arrays.asList(instruction)))
    		{
    			log.info(String.format("Failed to install ARP rules on switch ID : %d\n", switchId));
    			return false;
    		}
		}
		return true;
	}
	
	/***
	 * Add rules for table forwarding at switch designated by switchId
	 * @param switchId
	 * @return true if success, false otherwise
	 */
	private boolean addRulesForTableFwd(long switchId)
	{
		OFMatch match = new OFMatch();

		OFInstruction instruction = new OFInstructionGotoTable(shortestPathSwitchingApp.getTable());
		
		if(false == SwitchCommands.installRule(this.floodlightProv.getSwitch(switchId), this.table,
				PRIORITY_MED, match, Arrays.asList(instruction)))
		{
			log.info(String.format("Failed to install table forwarding rules on switch ID : %d\n", switchId));
			return false;
		}
	return true;
	}
	
	private boolean addRulesForVirtualIp(long switchId)
	{
		Collection<LoadBalancerInstance> loadBalancerList = this.instances.values();
		// Iterate through each LB
		for (LoadBalancerInstance lb : loadBalancerList)
		{
			OFMatch match = new OFMatch();
			List<OFMatchField> matchFields = new ArrayList<OFMatchField>();
			OFMatchField field1 = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
			OFMatchField field2 = new OFMatchField(OFOXMFieldType.IPV4_DST, lb.getVirtualIP());
			OFMatchField field3 = new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP);
			
			matchFields.add(field1);
			matchFields.add(field2);
			matchFields.add(field3);
			
			match.setMatchFields(matchFields);
			
			OFAction action = new OFActionOutput(OFPort.OFPP_CONTROLLER);
    		OFInstruction instruction = new OFInstructionApplyActions(Arrays.asList(action));
    		if(false == SwitchCommands.installRule(this.floodlightProv.getSwitch(switchId), this.table,
    				PRIORITY_MED, match, Arrays.asList(instruction)))
    		{
    			log.info(String.format("Failed to install Virtual IP rules on switch ID : %d\n", switchId));
    			return false;
    		}
		}
		return true;
		
	}
	
	/**
	 * Install all 3 sets of load balancing rules for a switch
	 * @param switchId = long ID for switch to add rules for
	 */
	private void addAllLoadBalancingRulesForSwitch(long switchId)
	{
		boolean check = true;
		check = check || this.addRulesForARP(switchId);
		check = check || this.addRulesForTableFwd(switchId);
		check = check || this.addRulesForVirtualIp(switchId);
		
		if(check == false)
		{
			log.info("There was an error installing one of the 3 sets of load balancing rules.\n"); 
		}
	}
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		log.info(String.format("Switch s%d added", switchId));
		this.addAllLoadBalancingRulesForSwitch(switchId);
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other packets                             */
		/*		THIS DOESN'T WORK PROPERLY YET (10:09PM Dec 24, 2017		 */
		/*********************************************************************/
		if(ethPkt.getEtherType() == Ethernet.TYPE_ARP)
		{
			// Send an ARP reply for ARP requests for virtual IPs
			ARP arpPkt = new ARP();
			arpPkt.setPayload(ethPkt.getPayload());
			Ethernet ethSendPacket = new Ethernet();
			
			int targetVirtualIP = IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress());
			byte[] mac = this.instances.get(targetVirtualIP).getVirtualMAC();
			
			ARP arpPacket = new ARP();
			ethSendPacket.setPayload(arpPacket);
			
			arpPacket.setOpCode(ARP.OP_REPLY);
			arpPacket.setProtocolType(ARP.PROTO_TYPE_IP);
			arpPacket.setProtocolAddressLength((byte)0x4);
			arpPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
			arpPacket.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
			arpPacket.setSenderHardwareAddress(mac);
			arpPacket.setTargetHardwareAddress(ethPkt.getSourceMACAddress());
			arpPacket.setSenderProtocolAddress(targetVirtualIP);
			arpPacket.setTargetProtocolAddress(IPv4.toIPv4Address(arpPkt.getSenderProtocolAddress()));
			
			if(false == SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ethSendPacket))
			{
				log.info(String.format("Failed to send ARP reply to destination IP %d, MAC %d", targetVirtualIP, mac[0]));
			}else
			{
				log.info(String.format("Sent ARP reply to destination IP %d, MAC %d", targetVirtualIP, mac[0]));
			}
		}else if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4)
		{
			IPv4 ipPacket = new IPv4();
			TCP tcpPacket = new TCP();
			ipPacket.setPayload(ethPkt.getPayload());
			tcpPacket.setPayload(ipPacket.getPayload());
			
			if(tcpPacket.getFlags() != TCP_FLAG_SYN)
			{
				return Command.CONTINUE;
			}else
			{
				// Send reset packet
				LoadBalancerInstance lb = this.instances.get(ipPacket.getDestinationAddress());
				int newDestIP = lb.getNextHostIP();
				byte[] newDestMAC = this.getHostMACAddress(newDestIP);
				//client
				OFMatch match = new OFMatch();
				List<OFMatchField> matchFields = new ArrayList<OFMatchField>();
				matchFields.add(new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP));
				matchFields.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
				matchFields.add(new OFMatchField(OFOXMFieldType.IPV4_SRC, ipPacket.getSourceAddress()));
				matchFields.add(new OFMatchField(OFOXMFieldType.IPV4_DST, ipPacket.getDestinationAddress()));
				matchFields.add(new OFMatchField(OFOXMFieldType.TCP_SRC, tcpPacket.getSourcePort()));
				matchFields.add(new OFMatchField(OFOXMFieldType.TCP_DST, tcpPacket.getDestinationPort()));
				
				List<OFAction> actions = new ArrayList<OFAction>();
				actions.add(new OFActionSetField(OFOXMFieldType.ETH_DST, newDestMAC));
				actions.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, newDestIP));
				List<OFInstruction> instructions = new ArrayList<OFInstruction>();
				instructions.add(new OFInstructionApplyActions(actions));
				instructions.add(new OFInstructionGotoTable(shortestPathSwitchingApp.getTable()));
				
				if(false == SwitchCommands.installRule(sw, this.table, PRIORITY_HI, match, instructions, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT))
				{
					log.info("Failed to install client->server rule for LB based on Ethernet packet recieved!\n");
				}
				else
				{
					log.info("Successfully installed client->server rule for LB based on Ethernet packet recieved!\n");
				}
				//server
				match = new OFMatch();
				matchFields = new ArrayList<OFMatchField>();
				matchFields.add(new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP));
				matchFields.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
				matchFields.add(new OFMatchField(OFOXMFieldType.IPV4_SRC, newDestIP));
				matchFields.add(new OFMatchField(OFOXMFieldType.IPV4_DST, ipPacket.getSourceAddress()));
				matchFields.add(new OFMatchField(OFOXMFieldType.TCP_SRC, tcpPacket.getDestinationPort()));
				matchFields.add(new OFMatchField(OFOXMFieldType.TCP_DST, tcpPacket.getSourcePort()));
				
				actions = new ArrayList<OFAction>();
				actions.add(new OFActionSetField(OFOXMFieldType.ETH_SRC, ethPkt.getDestinationMACAddress()));
				actions.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, ipPacket.getDestinationAddress()));
				instructions = new ArrayList<OFInstruction>();
				instructions.add(new OFInstructionApplyActions(actions));
				if(false == SwitchCommands.installRule(sw, this.table, PRIORITY_HI, match, instructions, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT))
				{
					log.info("Failed to install server->client rule for LB based on Ethernet packet recieved!\n");
				}
				else
				{
					log.info("Successfully installed server->client rule for LB based on Ethernet packet recieved!\n");
				}
			}
		}
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
