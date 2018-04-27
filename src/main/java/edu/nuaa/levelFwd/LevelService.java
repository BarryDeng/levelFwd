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
     *  Gets an existing Host level by hostId
     */
    LevelRule getHostLevel(HostId hostId);

    /**
     * Removes an existing Host informations by host id.
     */
    void removeHostInfo(HostId hostId);


    /**
     * Clear all Host informations and reset.
     */
    void clearHosts();

    /**
     * Get Level definition.
     */
    Level[] getLevelDef();
}
