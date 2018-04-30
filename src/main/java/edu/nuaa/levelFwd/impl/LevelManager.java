/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.nuaa.levelFwd.impl;

import com.google.common.collect.ImmutableSet;
import edu.nuaa.levelFwd.HostInfo;
import edu.nuaa.levelFwd.HostStore;
import edu.nuaa.levelFwd.Level;
import edu.nuaa.levelFwd.LevelRule;
import edu.nuaa.levelFwd.LevelService;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IP;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.IdGenerator;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.jdbc.DataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.util.Tools.groupedThreads;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
@Service
public class LevelManager implements LevelService {
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostStore hostStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DataSourceFactory dataSourceFactory;


    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private HostListener hostListener = new InternalHostListener();
//    private PacketProcessor processor = new ReactivePacketProcessor();
    private PacketProcessor processor = new InternalPacketListener();
    private IdGenerator idGenerator;

    private Connection conn = null;


    private ExecutorService blackHoleExecutor;

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    @Activate
    protected void activate(ComponentContext context) {
        appId = coreService.registerApplication("edu.nuaa.levelFwd");

        initMysqlConnection();

        packetService.addProcessor(processor, PacketProcessor.director(1));
        requestIntercepts();

        blackHoleExecutor = newSingleThreadExecutor(groupedThreads("onos/app/levelFwd",
                                                                   "black-hole-fixer",
                                                                   log));

        hostService.addListener(hostListener);

        idGenerator = coreService.getIdGenerator("host-ids");

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    private class InternalHostListener implements HostListener {

        @Override
        public void event(HostEvent event) {
            log.info("HOST CHANGED!!");

            if (event.type() == HostEvent.Type.HOST_ADDED) {
                HostInfo.Builder builder = HostInfo.builder();
                builder.hostId(event.subject().id());
                builder.vlanId(event.subject().vlan());
                builder.deviceId(event.subject().location().deviceId());
//                builder.Ip(event.subject().location().ipElementId().ipAddress().toIpPrefix());

                Set<IpAddress> addrs = event.subject().ipAddresses();
                if (addrs.isEmpty()) {
                    builder.Ip(IpAddress.valueOf("66.66.66.66"));
                } else {

                    builder.Ip(event.subject().ipAddresses().iterator().next());
                }
                builder.srcMAC(event.subject().mac());
                HostInfo new_host = builder.build();
                addHostInfo(new_host);
                log.info(String.format("New Host %s: %s", event.subject().id(), new_host.toString()));
            }
        }
    }

    private class InternalTopologyListener implements TopologyListener {
        @Override
        public void event(TopologyEvent event) {
            List<Event> reasons = event.reasons();
            if (reasons != null) {
                reasons.forEach(re -> {
                    if (re instanceof LinkEvent) {
                        LinkEvent le = (LinkEvent) re;
                        if (le.type() == LinkEvent.Type.LINK_REMOVED && blackHoleExecutor != null) {
                            blackHoleExecutor.submit(() -> fixBlackhole(le.subject().src()));
                        }
                    }
                });
            }
        }
    }

    // Wrapper class for a source and destination pair of MAC addresses
    private final class SrcDstPair {
        final MacAddress src;
        final MacAddress dst;

        private SrcDstPair(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            SrcDstPair that = (SrcDstPair) o;
            return Objects.equals(src, that.src) &&
                    Objects.equals(dst, that.dst);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }
    }


    private Set<FlowEntry> getFlowRulesFrom(ConnectPoint egress) {
        ImmutableSet.Builder<FlowEntry> builder = ImmutableSet.builder();
        flowRuleService.getFlowEntries(egress.deviceId()).forEach(r -> {
            if (r.appId() == appId.id()) {
                r.treatment().allInstructions().forEach(i -> {
                    if (i.type() == Instruction.Type.OUTPUT) {
                        if (((Instructions.OutputInstruction) i).port().equals(egress.port())) {
                            builder.add(r);
                        }
                    }
                });
            }
        });

        return builder.build();
    }


    private void fixBlackhole(ConnectPoint egress) {
        Set<FlowEntry> rules = getFlowRulesFrom(egress);
        Set<SrcDstPair> pairs = findSrcDstPairs(rules);

        Map<DeviceId, Set<Path>> srcPaths = new HashMap<>();

        for (SrcDstPair sd : pairs) {
            // get the edge deviceID for the src host
            Host srcHost = hostService.getHost(HostId.hostId(sd.src));
            Host dstHost = hostService.getHost(HostId.hostId(sd.dst));
            if (srcHost != null && dstHost != null) {
                DeviceId srcId = srcHost.location().deviceId();
                DeviceId dstId = dstHost.location().deviceId();
                log.trace("SRC ID is {}, DST ID is {}", srcId, dstId);

                cleanFlowRules(sd, egress.deviceId());

                Set<Path> shortestPaths = srcPaths.get(srcId);
                if (shortestPaths == null) {
                    shortestPaths = topologyService.getPaths(topologyService.currentTopology(),
                                                             egress.deviceId(), srcId);
                    srcPaths.put(srcId, shortestPaths);
                }
                backTrackBadNodes(shortestPaths, dstId, sd);
            }
        }
    }

    // Backtracks from link down event to remove flows that lead to blackhole
    private void backTrackBadNodes(Set<Path> shortestPaths, DeviceId dstId, SrcDstPair sd) {
        for (Path p : shortestPaths) {
            List<Link> pathLinks = p.links();
            for (int i = 0; i < pathLinks.size(); i = i + 1) {
                Link curLink = pathLinks.get(i);
                DeviceId curDevice = curLink.src().deviceId();

                // skipping the first link because this link's src has already been pruned beforehand
                if (i != 0) {
                    cleanFlowRules(sd, curDevice);
                }

                Set<Path> pathsFromCurDevice =
                        topologyService.getPaths(topologyService.currentTopology(),
                                                 curDevice, dstId);
                if (pickForwardPathIfPossible(pathsFromCurDevice, curLink.src().port()) != null) {
                    break;
                } else {
                    if (i + 1 == pathLinks.size()) {
                        cleanFlowRules(sd, curLink.dst().deviceId());
                    }
                }
            }
        }
    }

    // Removes flow rules off specified device with specific SrcDstPair
    private void cleanFlowRules(SrcDstPair pair, DeviceId id) {
        log.trace("Searching for flow rules to remove from: {}", id);
        log.trace("Removing flows w/ SRC={}, DST={}", pair.src, pair.dst);
        for (FlowEntry r : flowRuleService.getFlowEntries(id)) {
            boolean matchesSrc = false, matchesDst = false;
            for (Instruction i : r.treatment().allInstructions()) {
                if (i.type() == Instruction.Type.OUTPUT) {
                    // if the flow has matching src and dst
                    for (Criterion cr : r.selector().criteria()) {
                        if (cr.type() == Criterion.Type.ETH_DST) {
                            if (((EthCriterion) cr).mac().equals(pair.dst)) {
                                matchesDst = true;
                            }
                        } else if (cr.type() == Criterion.Type.ETH_SRC) {
                            if (((EthCriterion) cr).mac().equals(pair.src)) {
                                matchesSrc = true;
                            }
                        }
                    }
                }
            }
            if (matchesDst && matchesSrc) {
                log.trace("Removed flow rule from device: {}", id);
                flowRuleService.removeFlowRules((FlowRule) r);
            }
        }

    }

    // Returns a set of src/dst MAC pairs extracted from the specified set of flow entries
    private Set<SrcDstPair> findSrcDstPairs(Set<FlowEntry> rules) {
        ImmutableSet.Builder<SrcDstPair> builder = ImmutableSet.builder();
        for (FlowEntry r : rules) {
            MacAddress src = null, dst = null;
            for (Criterion cr : r.selector().criteria()) {
                if (cr.type() == Criterion.Type.ETH_DST) {
                    dst = ((EthCriterion) cr).mac();
                } else if (cr.type() == Criterion.Type.ETH_SRC) {
                    src = ((EthCriterion) cr).mac();
                }
            }
            builder.add(new SrcDstPair(src, dst));
        }
        return builder.build();
    }


    private void redirectPacket(PacketContext context, IpPrefix preDst, IpAddress dst) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(preDst)
                .build();

        TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
                .setIpDst(dst)
                .build();

        ForwardingObjective.Builder builder = DefaultForwardingObjective.builder();
        builder.withSelector(selector)
                .withTreatment(treatment1)
                .withPriority(10)
                .withFlag(ForwardingObjective.Flag.SPECIFIC)
                .fromApp(appId)
                .makePermanent();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), builder.add());
    }

    private boolean fakeArp(PacketContext context, Ethernet ethPkt) {
        if (!(ethPkt.getPayload() instanceof ARP)) return false;

        ARP arp = (ARP) ethPkt.getPayload();

        if (IpAddress.valueOf(IpAddress.Version.INET, arp.getTargetProtocolAddress()).getIp4Address()
                .equals(IpAddress.valueOf("10.0.0.254"))) {
//                    log.info(arp.toString());

            HostId id = HostId.hostId(ethPkt.getSourceMAC());
            LevelRule levelRule = getHostLevel(id);

            Ethernet resPkt = ARP.buildArpReply(Ip4Address.valueOf("10.0.0.254"), MacAddress.valueOf(levelRule.level().getPort()), ethPkt);

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(context.inPacket().receivedFrom().port())
                    .build();

            OutboundPacket response = new DefaultOutboundPacket(context.inPacket().receivedFrom().deviceId(),
                                                                treatment,
                                                                ByteBuffer.wrap(resPkt.serialize()));
            packetService.emit(response);

            return true;
        }

        return false;
    }

    private void initMysqlConnection() {
//        String url = "jdbc:mysql://localhost:3306/sdn?user=root&passwd=root&useUnicode=true&characterEncoding=UTF8";
        Properties dbProps = new Properties();
        dbProps.put(DataSourceFactory.JDBC_DATABASE_NAME, "sdn");
        dbProps.put(DataSourceFactory.JDBC_USER, "root");
        dbProps.put(DataSourceFactory.JDBC_PASSWORD, "root");
        dbProps.put(DataSourceFactory.JDBC_SERVER_NAME, "127.0.0.1");
        dbProps.put(DataSourceFactory.JDBC_PORT_NUMBER, "3306");

        try {
            DataSource dataSource = dataSourceFactory.createDataSource(dbProps);
            // Or
            // dataSourceFactory.createConnectionPoolDataSource(dbProps);
            conn = dataSource.getConnection();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void storeToMysqlDatabase(Ethernet pkt) {
        String sql;
        try {
            Statement stmt = conn.createStatement();

            IPv4 ipv4 = null;
            TCP tcp = null;
            UDP udp = null;
            ICMP icmp = null;
            if (pkt.getPayload() instanceof IPv4) {
                ipv4 = (IPv4) pkt.getPayload();

                if (ipv4.getPayload() instanceof TCP) {
                    tcp = (TCP) ipv4.getPayload();
                } else if (ipv4.getPayload() instanceof UDP) {
                    udp = (UDP) ipv4.getPayload();
                } else if (ipv4.getPayload() instanceof ICMP) {
                    icmp = (ICMP) ipv4.getPayload();
                }
            }

            String dl_src = pkt.getSourceMAC().toString(),
                    dl_dst = pkt.getDestinationMAC().toString(),
                    nw_src = "", nw_dst = "", nw_proto="",
                    src_port = "", dst_port = "";

            int nw_length = 0, vlan_id = pkt.getVlanID(), tcp_flags = 0, tcp_seq = 0, tcp_ack = 0;
            if (ipv4 != null) {
                nw_src = Ip4Address.valueOf(ipv4.getSourceAddress()).toString();
                nw_dst = Ip4Address.valueOf(ipv4.getDestinationAddress()).toString();
                nw_proto = String.valueOf(ipv4.getProtocol());
                nw_length = ipv4.getTotalLength();
            }
            if (tcp != null) {
                src_port = String.valueOf(tcp.getSourcePort());
                dst_port = String.valueOf(tcp.getDestinationPort());
                tcp_ack = tcp.getAcknowledge();
                tcp_seq = tcp.getSequence();
                tcp_flags = tcp.getFlags();
            }
            if (udp != null) {
                src_port = String.valueOf(udp.getSourcePort());
                dst_port = String.valueOf(udp.getDestinationPort());
            }
            if (icmp != null) {
                src_port = String.valueOf(icmp.getIcmpType());
                dst_port = String.valueOf(icmp.getIcmpCode());
            }

            sql = String.format("insert into sdn (dl_src, dl_dst, vlan_id, nw_src," +
                                        " nw_dst, nw_proto, nw_length, src_port, " +
                                        "dst_port, tcp_flags, tcp_seq, tcp_ack) values " +
                                        "('%s', '%s', %d, '%s', '%s', '%s', %d, '%s', '%s', %d, %d, %d)",
                                dl_src, dl_dst, vlan_id, nw_src, nw_dst,
                                nw_proto, nw_length, src_port, dst_port,
                                tcp_flags, tcp_seq, tcp_ack);
            if (stmt.execute(sql)) {
                log.info("Insert OK!");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private class InternalPacketListener implements PacketProcessor {

        @Override
        public void process(PacketContext context) {

            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            storeToMysqlDatabase(ethPkt);



            MacAddress macAddress = ethPkt.getSourceMAC();
            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            HostId id = HostId.hostId(ethPkt.getDestinationMAC()),
                    id2 = HostId.hostId(ethPkt.getSourceMAC());

            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                return;
            }

//            fakeArp(context, ethPkt);

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);

//            if (pkt.receivedFrom().deviceId().equals(dst2.location().deviceId())) {
//                Set<Host> hosts = hostService.getHostsByIp(IpAddress.valueOf("10.0.0.254"));
//
//                if (!hosts.isEmpty()) {
//                    Host host = hosts.iterator().next();
//                    if (ethPkt.getSourceMAC().equals(host.mac()) &&
//                            pkt.receivedFrom().deviceId().equals(host.location().deviceId())) {
//
//                        HostId hostid = HostId.hostId(ethPkt.getDestinationMAC());
//                        LevelRule levelRule = getHostLevel(hostid);
//                        if (pkt.receivedFrom().port().equals(PortNumber.portNumber(levelRule.level().getPort()))) {
//                            log.info("test function");
//                            return;
//                        }
//
//                    }
//                }
//            }

            if (dst == null) {
                flood(context);
                return;
            }

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    Set<Host> hosts = hostService.getHostsByIp(IpAddress.valueOf("10.0.0.254"));

                    if (!hosts.isEmpty()) {
                        Host host = hosts.iterator().next();
                        if (ethPkt.getDestinationMAC().equals(host.mac()) &&
                                pkt.receivedFrom().deviceId().equals(host.location().deviceId())) {

                            HostId hostid = HostId.hostId(ethPkt.getSourceMAC());
                            LevelRule levelRule = getHostLevel(hostid);
                            installRule(context, PortNumber.portNumber(levelRule.level().getPort()));
                            log.info("Redirect forwarding port based on user level");
                            return;
                        }
                    }
                    installRule(context, dst.location().port());
                }
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                                             pkt.receivedFrom().deviceId(),
                                             dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                flood(context);
                return;
            }

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                         pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }

            // Otherwise forward and be done with it.
            installRule(context, path.src().port());

        }
    }

    @Override
    public List<HostInfo> getHostInfos(){
        return hostStore.getHostInfos();
    }

    @Override
    public void addHostInfo(HostInfo host){
        hostStore.addHostInfo(host);
    }

    /**r
     * Gets an existing Host information.
     */
    @Override
    public HostInfo getHostInfo(HostId hostId) {
        return hostStore.getHostInfoById(hostId);
    }

    /**
     *  Gets an existing Host level by hostId
     */
    @Override
    public LevelRule getHostLevel(HostId hostId){
        return hostStore.getHostLevelById(hostId);
    }
    /**
     * Removes an existing Host infomations by host id.
     */
    @Override
    public void removeHostInfo(HostId hostId) {
        hostStore.removeHostInfo(hostId);
    }

    /**
     * Clear all Host infomations and reset.
     */
    @Override
    public void clearHosts(){
        hostStore.clearHosts();
    }

    /**
     * Get Level definition.
     */
    @Override
    public Level[] getLevelDef() {
        return Level.values();
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber) {
        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();



        // If PacketOutOnly or ARP packet than forward directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC());

        if (inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
            byte ipv4Protocol = ipv4Packet.getProtocol();
            Ip4Prefix matchIp4SrcPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                      Ip4Prefix.MAX_MASK_LENGTH);
            Ip4Prefix matchIp4DstPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                      Ip4Prefix.MAX_MASK_LENGTH);
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(matchIp4SrcPrefix)
                    .matchIPDst(matchIp4DstPrefix);

            if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                        .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
            }
            if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                        .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
            }
            if (ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchIcmpType(icmpPacket.getIcmpType())
                        .matchIcmpCode(icmpPacket.getIcmpCode());
            }
        }

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(10)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(10)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                                     forwardingObjective);
        //
        // If packetOutOfppTable
        //  Send packet back to the OpenFlow pipeline to match installed flow
        // Else
        //  Send packet direction on the appropriate port
        //

        packetOut(context, portNumber);

    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                                             context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }
}
