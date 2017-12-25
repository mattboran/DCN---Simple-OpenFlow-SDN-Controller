package edu.nyu.cs.sdn.apps.sps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.factory.OFActionFactory;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.Host;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
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
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);		
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }
    
    /**
     *  Filter links by unique only, since links are bi-directional
     * @return list of unique links
     */
    private Collection<Link> getAllUniqueLinks() 
    {
    	Collection<Link> links = this.getLinks();
    	Collection<Link> unique = new ArrayList<Link>();
    	
    	// Go through all links and check if they've been seen already. If they haven't put them in unique
    	// if they have, ignore and continue
    	for(Link l : links)
    	{
    		boolean linkIsUnique = true;
    		for(Link current : unique)
    		{
    			if(((l.getSrc() == current.getSrc()) && (l.getDst() == current.getDst())))
    			{
    				linkIsUnique = false;
    				break;
    			}
    			else if(((l.getDst() == current.getSrc()) && (l.getSrc() == current.getDst())))
    			{
    				linkIsUnique = false;
    				break;
    			}
    		}
    		if(linkIsUnique)
    		{
    			unique.add(l);
    		}
    	}
    	return unique;
    }
    
    /**
     * Get all outgoing links from a switch
     * @param swId id of the switch
     * @param links = list of links to consider
     * @return list of links incident to the switch
     */
    private Collection<Link> getIncedentLinks(long swId, Collection<Link> links)
    {
    	Collection<Link> incedentLinks = new ArrayList<Link>();
   
    	for(Link l: links)
    	{
    		if(l.getSrc() == swId || l.getDst() == swId)
    		{
    			incedentLinks.add(l);
    		}
    	}
    	return incedentLinks;
    }
    /**
     * Bellman-Ford using a queue to define which edges to explore next
     * 		This is a simplified version which is O(V*E)
     * @param pathStart - the switch that the packet originates from 
     * 					(host->switch->->...path...->->switch->host)
     * @return shortest path tree in the form of ConcurrentHashMap, where each entry is from the switch ID
     * to the destination port (where to send a packet to the next switch on)
     */
    private ConcurrentHashMap<Long, Integer> getBestRoutesToHost(IOFSwitch pathStartSwitch) 
    {
    	ConcurrentHashMap<Long, Integer> parent = new ConcurrentHashMap<Long, Integer>();
    	ConcurrentHashMap<Long, Integer> distances = new ConcurrentHashMap<Long, Integer>();
    	Queue<Long> Q = new LinkedList<Long>();

        Collection<IOFSwitch> switchList = this.getSwitches().values();
        
        // Remove cases where destination == source too
    	Collection<Link> linksList = this.getAllUniqueLinks();

    	// Initialize shortest path with source = pathStartSwitch
    	for (IOFSwitch sw : switchList) 
    	{
    	    if(sw.getId() == pathStartSwitch.getId())
    	    {
    	    	distances.put(sw.getId(), 0);
    	    }
    	    else
    	    {
    	    	distances.put(sw.getId(), Integer.MAX_VALUE - 1);
    	    }
    	}
    	// Bellman Ford using a queue to which switches should be explored next
    	for (int i = 0; i < switchList.size(); i++) 
    	{
    	    linksList = this.getAllUniqueLinks();
    	    Q.add(pathStartSwitch.getId());
    	    
    	    while(Q.isEmpty() == false) 
    	    {
	    		long swId = Q.remove();
	    		Collection<Link> outLinks = this.getIncedentLinks(swId, linksList);
	    	    
	    		for(Link outLink : outLinks) 
	    		{
	    		    int currDist = distances.get(swId);
	    		    int nextDist = Integer.MAX_VALUE - 1;
	    		    
	    		    if(swId == outLink.getSrc()) 
	    		    { 
		    			nextDist = distances.get(outLink.getDst());
		    			// Relax edge
		    			if(nextDist > (currDist + 1)) 
		    			{
		    			    parent.put(outLink.getDst(), outLink.getDstPort());
		    			    distances.put(outLink.getDst(), (currDist + 1));
		    			}
		
		    			Q.add(outLink.getDst());
	    		    } 
	    		    else 
	    		    { 
		    			nextDist = distances.get(outLink.getSrc());
		    			// Relax edge
		    			if(nextDist > (currDist + 1)) {
		    			    parent.put(outLink.getSrc(), outLink.getSrcPort());
		    			    distances.put(outLink.getSrc(), (currDist + 1));
		    			}
		
		    			Q.add(outLink.getSrc());
	    		    }
	
	    		    linksList.remove(outLink);
	    		}

    	    }
    	}	

    	return parent;
    }
    
    /**
     * Install rules on all switches on the network for a host
     * @param h the host we're installing rules for
     * @return false if any installRule call fails, true otherwise
     */
    private boolean addHostRules(Host h)
    {
    	if (!h.isAttachedToSwitch())
    	{
    		log.info(String.format("Trying to add rules to host %s that's not attached to a switch!", h.getName()));
    		return false;
    	}
    	else
    	{
    		boolean retVal = true;
    		Map<Long, Integer> shortestPaths = getBestRoutesToHost(h.getSwitch());
    		// Use set instead of collection to enforce no duplicates
    		Set<Long> swIds = shortestPaths.keySet();
    		
    		OFMatch match = new OFMatch();
    		List<OFMatchField> matchFields = new ArrayList<OFMatchField>();
    		OFMatchField field1 = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
    		OFMatchField field2 = new OFMatchField(OFOXMFieldType.IPV4_DST, h.getIPv4Address());
    		
    		matchFields.add(field1);
    		matchFields.add(field2);
    		
    		match.setMatchFields(matchFields);
    		
    		//log.info(String.format("\n--Installing IPv4 rule for host IP: %s\t connected to switch %d\n " ,IPv4.fromIPv4Address(h.getIPv4Address()),h.getSwitch().getId()));
    		
    		// Add rule for host -> switch ->...path... -> other switches
    		for (Long swId : swIds)
    		{
    			OFAction action = new OFActionOutput(shortestPaths.get(swId));
    			OFInstruction instruction = new OFInstructionApplyActions(Arrays.asList(action));
    			
    			retVal = SwitchCommands.installRule(this.getSwitches().get(swId), this.table,
    					SwitchCommands.DEFAULT_PRIORITY, match, Arrays.asList(instruction));
    			
    			log.info(String.format("Host %s installing for switch %s, next switch we fwd on port %d",
    					h.getName(), swId, shortestPaths.get(swId)));
    			if (retVal == false)
    			{
    				log.info(String.format("Failed to add rule for %s host-> switch at addr: %s!\n", 
        					h.getName(), this.getSwitches().get(swId).getInetAddress().toString()));
    				return retVal;
    			}
    		}
    		
    		// Finally add rule for host->switch
    		OFAction action = new OFActionOutput(h.getPort());
    		OFInstruction instruction = new OFInstructionApplyActions(Arrays.asList(action));
    		retVal = SwitchCommands.installRule(h.getSwitch(), this.table, SwitchCommands.DEFAULT_PRIORITY,
    											match, Arrays.asList(instruction));
    		if (retVal == false)
    		{
    			log.info(String.format("Failed to add rule for %s host-> switch at addr: %s!\n", 
    					h.getName(), h.getSwitch().getInetAddress().toString()));
    		}
    		
    		return retVal;
    	}
    }
    
    /**
     * Remove the rules in all switches for a given host
     * @param h the host
     * @return true if remove rules success, false otherwise
     */
    private boolean removeHostRules(Host h)
    {
    	if(h.getIPv4Address() == null)
    	{
    		return false;
    	}
    	boolean retVal = true;
    	
    	OFMatch match = new OFMatch();
    	List<OFMatchField> matchFields = new ArrayList<OFMatchField>();
		OFMatchField field1 = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
		OFMatchField field2 = new OFMatchField(OFOXMFieldType.IPV4_DST, h.getIPv4Address());
		
		matchFields.add(field1);
		matchFields.add(field2);
		
		match.setMatchFields(matchFields);
		
		//log.info(String.format("\n--Removing IPv4 rule for host IP: %s\t connected to switch %d\n " ,IPv4.fromIPv4Address(h.getIPv4Address()),h.getSwitch().getId()));
		
    	for(IOFSwitch sw : this.getSwitches().values())
    	{
    		retVal = SwitchCommands.removeRules(sw, this.table, match);
    		if(retVal == false)
    		{
    			log.info(String.format("Failed to remove rule for %s host-> switch at addr: %s!\n", 
    					h.getName(), sw.getInetAddress().toString()));
    			return retVal;
    		}
    	}
    	return retVal;
    }
    
    /**
     * Iterate through all hosts, remove existing host rules, apply new ones.
     * @return true if success, otherwise false
     */
    private boolean applyAllRules()
    {
    	for(Host h : this.getHosts())
		{
			if(this.removeHostRules(h) == false)
			{
				log.info(String.format("Apply all rules - remove host rules failure for host %s\n", h.getName()));
				return false;
			}
			if(this.addHostRules(h)==false)
			{
				log.info(String.format("Apply all rules - add host rules failure for host %s \n", h.getName()));
				return false;
			}
		}
    	return true;
    }
    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);

			if(this.addHostRules(host) == false)
			{
				log.info(String.format("There was an error adding host %s\n", host.getName()));
			}

		}
	}
			

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (host != null)
		{
			this.knownHosts.remove(host);
			log.info(String.format("Host %s is no longer attached to a switch", 
					host.getName()));
			
			if(this.removeHostRules(host) == false)
			{
				log.info(String.format("There was an error removing host %s\n", host.getName()));
			}
		}		
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		this.removeHostRules(host);
		this.addHostRules(host);
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		//Iterate through all hosts, remove existing rules, add new updated rules
		this.applyAllRules();
		
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		log.info(String.format("Switch s%d removed", switchId));
		
		//Iterate through all hosts, remove existing rules, add new updated rules
		this.applyAllRules();
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
				}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
			//Iterate through all hosts, remove existing rules, add new updated rules
			this.applyAllRules();
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}