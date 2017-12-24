package edu.nyu.cs.sdn.apps.sps;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface InterfaceShortestPathSwitching extends IFloodlightService
{
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable();
}
