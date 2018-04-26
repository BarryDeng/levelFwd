package edu.nuaa.levelFwd;

import org.onosproject.net.HostId;

import java.util.List;

public interface LevelService {

    /**
     * Gets a list containing all Host informations.
     */
    List<HostInfo> getHostInfos();


    /**
     * Adds a new Host informations.
     */
    void addHostInfo(HostInfo host);


    /**
     * Gets an existing Host informations.
     */
    HostInfo getHostInfo(HostId hostId);


    /**
     * Removes an existing Host informations by host id.
     */
    void removeHostInfo(HostId hostId);


    /**
     * Clear all Host informations and reset.
     */
    void clearHosts();
}
