package edu.nuaa.levelFwd;

import org.onosproject.net.HostId;

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
    HostInfo getHostInfo(HostId hostId);

    /**
     *  Gets an existing Host level by hostId
     */
    LevelRule getHostLevel(HostId hostId);

    /**
     * Removes an existing Host infomations by host id.
     */
    void removeHostInfo(HostId hostId);


    /**
     * Clear all Host infomations and reset.
     */
    void clearHosts();
}
