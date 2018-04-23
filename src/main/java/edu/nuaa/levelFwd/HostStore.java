
package edu.nuaa.levelFwd;

import org.onlab.packet.MacAddress;
import org.onosproject.store.Store;

import java.util.List;

public interface HostStore extends Store {

    /**
     * Gets a list containing all Host infomations.
     */
    List<HostInfo> getHostInfos();


    /**
     * Adds a new Host infomations.
     */
    void addHostInfo(HostInfo host);


    /**
     * Gets an existing Host infomations.
     */
    HostInfo getHostInfoById(HostsId hostsId);

    HostInfo getHostInfoByMAC(MacAddress srcMac);


    /**
     * Removes an existing Host infomations by host id.
     */
    void removeHostInfo(HostsId hostsId);


    /**
     * Clear all Host infomations and reset.
     */
    void clearHosts();
}
