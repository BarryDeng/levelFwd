package edu.nuaa.levelFwd.impl;

import com.google.common.collect.Collections2;
import edu.nuaa.levelFwd.HostInfo;
import edu.nuaa.levelFwd.HostStore;
import edu.nuaa.levelFwd.LevelRule;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.MacAddress;
import org.onlab.util.KryoNamespace;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.HostId;
import org.onosproject.store.AbstractStore;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Implementation of the hosts store service.
 */
@Component(immediate = true)
@Service
public class DistributeHostInfoStore extends AbstractStore implements HostStore {

    private final Logger log = getLogger(getClass());
    private final int defaultFlowMaxPriority = 30000;

    private ConsistentMap<HostId, HostInfo> hostSet; // Host信息记录
    private ConsistentMap<DeviceId, Integer> deviceToPriority; // Device优先级
    private ConsistentMap<HostId, Set<String>> hostToService; // 主机可以访问的服务类型
    private ConsistentMap<HostId, LevelRule> hostToLevel; // 主机对应的安全级别

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Activate
    public void activate() {
        ApplicationId appId = coreService.getAppId("edu.nuaa.levelFwd");

        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(HostInfo.class)
                .register(LevelRule.class)
                .register(MacAddress[].class)
                .register(TreeSet.class)
                .register(LevelRule.Level.class);

        hostSet = storageService.<HostId, HostInfo>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("host-info-set")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();

        deviceToPriority = storageService.<DeviceId, Integer>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("device-to-priority")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();

        hostToService = storageService.<HostId, Set<String>>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("host-service-set")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();

        hostToLevel = storageService.<HostId, LevelRule>consistentMapBuilder()
                .withSerializer(Serializer.using(serializer.build()))
                .withName("host-levelrule-set")
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();

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
        hostToLevel.putIfAbsent(host.id(), host.rule());
        hostToService.putIfAbsent(host.id(), host.rule().service());
    }

    @Override
    public HostInfo getHostInfoById(HostId hostId) {
        Versioned<HostInfo> host = hostSet.get(hostId);
        if (host != null) {
            return host.value();
        } else {
            return null;
        }
    }

    @Override
    public LevelRule getHostLevelById(HostId hostId){
        Versioned<LevelRule> level = hostToLevel.get(hostId);
        if (level != null) {
            return level.value();
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
        hostToService.clear();
        hostToLevel.clear();
    }
}