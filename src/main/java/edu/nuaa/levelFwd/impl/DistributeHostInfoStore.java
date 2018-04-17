package edu.nuaa.levelFwd.impl;

import com.google.common.collect.Collections2;
import edu.nuaa.levelFwd.HostId;
import edu.nuaa.levelFwd.HostInfo;
import edu.nuaa.levelFwd.HostStore;
import edu.nuaa.levelFwd.LevelRule;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.store.AbstractStore;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;


/**
 * Implementation of the hosts store service.
 */
@Component(immediate = true)
@Service
public class DistributeHostInfoStore extends AbstractStore implements HostStore {


    private final Logger log = getLogger(getClass());
    private final int defaultFlowMaxPriority = 30000;

    private ConsistentMap<HostId, HostInfo> hostSet;
    private ConsistentMap<DeviceId, Integer> deviceToPriority;
    private ConsistentMap<HostId, Set<String>> hostToService;
    private ConsistentMap<HostId, LevelRule> hostToLevel;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;


    @Activate
    public void activate() {
        log.info("Started");
    }

    @Deactivate
    public void deactive() {
        log.info("Stopped");
    }

    @Override
    public List<HostInfo> getHostInfos() {
        List<HostInfo> hostInfos = new ArrayList<>();
        hostInfos.addAll(Collections2.transform(hostSet.values(), Versioned::value));
        return hostInfos;
    }

    @Override
    public void addHostInfo(HostInfo host) {
        hostSet.putIfAbsent(host.id(), host);
    }

    @Override
    public HostInfo getHostInfo(HostId hostId) {
        Versioned<HostInfo> host = hostSet.get(hostId);
        if (host != null) {
            return host.value();
        } else {
            return null;
        }
    }

    @Override
    public void removeHostInfo(HostId hostId) {
        hostSet.remove(hostId);
    }

    @Override
    public void clearHosts() {
        hostSet.clear();
        deviceToPriority.clear();
    }
}