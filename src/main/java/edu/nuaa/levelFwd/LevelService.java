package edu.nuaa.levelFwd;

import java.util.List;

public interface LevelService {

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
    HostInfo getHostInfo(HostsId hostsId);


    /**
     * Removes an existing Host infomations by host id.
     */
    void removeHostInfo(HostsId hostsId);


    /**
     * Clear all Host infomations and reset.
     */
    void clearHosts();
}
