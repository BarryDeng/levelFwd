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
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
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
import org.onosproject.net.edge.EdgePortListener;
import org.onosproject.net.edge.EdgePortService;
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
import org.onosproject.net.neighbour.NeighbourMessageHandler;
import org.onosproject.net.neighbour.NeighbourResolutionService;
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
    protected EdgePortService edgeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NeighbourResolutionService neighbourResolutionService;

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
    private PacketProcessor processor = new InternalPacketListener();
    private IdGenerator idGenerator;

    private Connection conn = null;

    private EdgePortListener edgeListener = new InternalEdgeListener(this);
    private NeighbourMessageHandler defaultHandler = new InternalNeighbourMessageHandler(this);

    private ExecutorService blackHoleExecutor;

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
//        selector.matchEthType(Ethernet.TYPE_ARP);
//        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    @Activate
    protected void activate(ComponentContext context) {
        appId = coreService.registerApplication("edu.nuaa.levelFwd");
        idGenerator = coreService.getIdGenerator("host-ids");
        initMysqlConnection();

        packetService.addProcessor(processor, PacketProcessor.director(1));
        requestIntercepts();

        blackHoleExecutor = newSingleThreadExecutor(groupedThreads("onos/app/levelFwd",
                                                                   "black-hole-fixer",
                                                                   log));

        hostService.addListener(hostListener);
        hostService.getHosts().forEach(this::addHostDefault);

        edgeService.addListener(edgeListener);
        edgeService.getEdgePoints().forEach(this::addDefault);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        edgeService.removeListener(edgeListener);
        processor = null;
        log.info("Stopped");
    }

    /**
     * EdgeService port handle functions
     * addDefault
     * removeDefault
     * isIpInSpecial
     * recoverIpToNormal
     */
    void addDefault(ConnectPoint port) {
        neighbourResolutionService.registerNeighbourHandler(port, defaultHandler, appId);
    }

    void removeDefault(ConnectPoint port) {
        neighbourResolutionService.unregisterNeighbourHandler(port, defaultHandler, appId);
    }

    public boolean isIpInSpecial(IpAddress ip) {
        byte[] ipArr = ip.toOctets();
        return ipArr[1] != 0;
    }

    public IpAddress recoverIpToNormal(IpAddress ip) {
        byte[] ipArr = ip.toOctets();
        ipArr[1] = 0;
        return IpAddress.valueOf(IpAddress.Version.INET, ipArr);
    }

    /**
     * HostService host add function
     */
    private void addHostDefault(Host host) {
        HostInfo.Builder builder = HostInfo.builder();
        builder.hostId(host.id());
        builder.vlanId(host.vlan());
        builder.deviceId(host.location().deviceId());

        Set<IpAddress> addrs = host.ipAddresses();
        if (addrs.isEmpty()) {
            builder.Ip(IpAddress.valueOf("66.66.66.66"));
        } else {
            builder.Ip(host.ipAddresses().iterator().next());
        }
        builder.srcMAC(host.mac());
        HostInfo new_host = builder.build();
        addHostInfo(new_host);
        log.info(String.format("New Host %s: %s", host.id(), new_host.toString()));
    }

    private class InternalHostListener implements HostListener {

        @Override
        public void event(HostEvent event) {
            log.info("HOST CHANGED!!");

            if (event.type() == HostEvent.Type.HOST_ADDED) {
                addHostDefault(event.subject());
            }
        }
    }

    /**
     * MySQL initialization
     */
    private void initMysqlConnection() {
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

    /**
     * Store each pkt in MySQL
     * @param pkt
     */
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

        // Ipv4
        private boolean addrInMiddleBox(IpAddress addr) {
            IpAddress[] middleboxes = new IpAddress[]{
                    IpAddress.valueOf("10.1.0.254"),
                    IpAddress.valueOf("10.2.0.254"),
                    IpAddress.valueOf("10.3.0.254"),
                    IpAddress.valueOf("10.4.0.254"),
                    IpAddress.valueOf("10.5.0.254")
            };
            for (IpAddress item : middleboxes) {
                if (addr.equals(item)) {
                    return true;
                }
            }
            return false;
        }

        // MAC
        private boolean addrInMiddleBox(MacAddress addr) {
            // TODO: HACK!
            MacAddress[] middleboxes = new MacAddress[]{
                    MacAddress.valueOf("00:00:00:00:01:00"),
                    MacAddress.valueOf("00:00:00:01:02:00"),
                    MacAddress.valueOf("00:00:00:02:03:00"),
            };
            for (MacAddress item : middleboxes) {
                if (item.equals(addr)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Host IpAddress NAT
         * @direction == 1 10.0.0.* -> 10.1.0.*
         * @direction == 2 10.1.0.* -> 10.0.0.*
         */
        private IpAddress nat(IpAddress addr, int direction) {
            IpAddress[] src = new IpAddress[]{
                    IpAddress.valueOf("10.0.0.1"),
                    IpAddress.valueOf("10.0.0.2"),
                    IpAddress.valueOf("10.0.0.3"),
                    IpAddress.valueOf("10.0.0.4"),
                    IpAddress.valueOf("10.0.0.5"),
                    IpAddress.valueOf("10.0.0.6"),
            };

            IpAddress[] dst = new IpAddress[]{
                    IpAddress.valueOf("10.1.0.1"),
                    IpAddress.valueOf("10.1.0.2"),
                    IpAddress.valueOf("10.1.0.3"),
                    IpAddress.valueOf("10.1.0.4"),
                    IpAddress.valueOf("10.1.0.5"),
                    IpAddress.valueOf("10.1.0.6"),
            };

            if (direction == 1) {
                for (int i = 0; i < src.length; ++i) {
                    if (src[i].equals(addr)) {
                        return dst[i];
                    }
                }
            } else {
                for (int i = 0; i < dst.length; ++i) {
                    if (dst[i].equals(addr)) {
                        return src[i];
                    }
                }
            }
            log.info("NAT: " + addr.toString() + " " + direction + " ERROR! ");
            return null;
        }

        /**
         * GetWay IpAddress NAT follow by hostLevel
         * @direction == 1 10.0.0.254 -> 10.*.0.254
         * @direction == 2 10.*.0.254 -> 10.0.0.254
         */
        private IpAddress nat2(IpAddress src, int direction) {
            IpAddress[] srcs = new IpAddress[]{
                    IpAddress.valueOf("10.0.0.1"),
                    IpAddress.valueOf("10.0.0.2"),
                    IpAddress.valueOf("10.0.0.3"),
                    IpAddress.valueOf("10.0.0.4"),
                    IpAddress.valueOf("10.0.0.5"),
                    IpAddress.valueOf("10.0.0.6"),
            };

            IpAddress[] dsts = new IpAddress[]{
                    IpAddress.valueOf("10.1.0.254"),
                    IpAddress.valueOf("10.1.0.254"),
                    IpAddress.valueOf("10.1.0.254"),
                    IpAddress.valueOf("10.1.0.254"),
                    IpAddress.valueOf("10.1.0.254"),
                    IpAddress.valueOf("10.1.0.254"),
            };

            if (direction == 1) {
                for (int i = 0; i < srcs.length; ++i) {
                    if (srcs[i].equals(src)) {
                        return dsts[i];
                    }
                }
            } else {
                return IpAddress.valueOf("10.0.0.254");
            }
            log.info("NAT2: " + src.toString() + " " + direction + " ERROR! ");
            return null;
        }

        // Indicates whether this is a control packet, e.g. LLDP, BDDP
        private boolean isControlPacket(Ethernet eth) {
            short type = eth.getEtherType();
            return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
        }

        // Install a rule forwarding the packet to the specified port.
        private void installRule(PacketContext context, Ethernet inPkt, byte[] src, byte[] dst, PortNumber portNumber) {
            //
            // We don't support (yet) buffer IDs in the Flow Service so
            // packet out first.
            //
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
            if (src != null && dst != null){
                TrafficTreatment.Builder treatmentbuilder = DefaultTrafficTreatment.builder();
                if (!Ip4Address.valueOf(src).equals(Ip4Address.ZERO)) {
                    treatmentbuilder.setIpSrc(IpAddress.valueOf(IpAddress.Version.INET, src));
                }
                if (!Ip4Address.valueOf(dst).equals(Ip4Address.ZERO)) {
                    treatmentbuilder.setIpDst(IpAddress.valueOf(IpAddress.Version.INET, dst));
                }
                TrafficTreatment treatment = treatmentbuilder.setOutput(portNumber)
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
            }
            else {
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
        }

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

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                return;
            }

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                flood(context);
                return;
            }

            // IpAddress NAT when the packet arrived the edge OVS
            if (pkt.receivedFrom().deviceId().equals(DeviceId.deviceId("of:0000000000010201"))) {
                if (pkt.parsed().getEtherType() == Ethernet.TYPE_IPV4) {
                    Ethernet ethpkt = pkt.parsed();
                    IPv4 iPv4 = (IPv4) ethpkt.getPayload();
                    // IPv4 send from middlebox
                    // DST 10.1.0.* -> 10.0.0.*
                    // SRC 10.*.0.254 -> 10.0.0.254
                    if (addrInMiddleBox(ethpkt.getSourceMAC())) {
                        // Don't handle OSPF Packet.
                        if (iPv4.getProtocol() == 89) {
                            return;
                        }

                        PortNumber port = PortNumber.FLOOD;

                        if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                            if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                                port = dst.location().port();
                            }
                        } else {
                            Set<Path> paths =
                                    topologyService.getPaths(topologyService.currentTopology(),
                                                             pkt.receivedFrom().deviceId(),
                                                             dst.location().deviceId());
                            if (paths.isEmpty()) {
                                Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
                                if (path == null) {
                                    log.warn("Don't know where to go from here {} for {} -> {}",
                                             pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                                } else {
                                    port = path.src().port();
                                }
                            }
                        }

                        byte[] modsrc = Ip4Address.ZERO.toOctets();
                        byte[] moddst = Ip4Address.ZERO.toOctets();

                        // Get dst host level
                        // Nat middle box IpAddress by host level
                        HostId hostid = HostId.hostId(ethPkt.getDestinationMAC());
                        LevelRule level = getHostLevel(hostid);

                        moddst = nat(IpAddress.valueOf(iPv4.getDestinationAddress()), 2).toOctets();
                        if (addrInMiddleBox(IpAddress.valueOf(iPv4.getSourceAddress()))) {
                            // modsrc = nat2(IpAddress.valueOf(iPv4.getSourceAddress()), 2).toOctets();
                            modsrc = level.level().natByLevel(2).toOctets();
                        }
                        installRule(context, context.inPacket().parsed(), modsrc, moddst, port);

                        iPv4.setDestinationAddress(nat(IpAddress.valueOf(iPv4.getDestinationAddress()), 2).toString());
                        // If SRC is MiddleBox then change ip SRC.
                        if (addrInMiddleBox(IpAddress.valueOf(iPv4.getSourceAddress()))) {
                            //iPv4.setSourceAddress(nat2(IpAddress.valueOf(iPv4.getSourceAddress()), 2).toString());
                            iPv4.setSourceAddress(level.level().natByLevel(2).toString());
                        }
                        iPv4.resetChecksum();

                        ethpkt.setPayload(iPv4);
                        OutboundPacket outboundPacket = new DefaultOutboundPacket(context.inPacket().receivedFrom().deviceId(),
                                                                                  context.treatmentBuilder().setOutput(port).build(),
                                                                                  ByteBuffer.wrap(ethpkt.serialize()));
                        packetService.emit(outboundPacket);
                        context.block();
                        return;
                        // IPv4 send from host && DST in middlebox
                        // SRC: 10.0.0.* -> 10.1.0.*
                        // DST: 10.0.0.254 -> 10.*.0.254
                    } else if (addrInMiddleBox(ethpkt.getDestinationMAC())) {
                        // If DST is MiddleBox then change ip DST.
                        PortNumber port = dst.location().port();

                        byte[] modsrc = Ip4Address.ZERO.toOctets();
                        byte[] moddst = Ip4Address.ZERO.toOctets();

                        // Get src host level
                        // Nat middle box IpAddress by host level
                        HostId hostid = HostId.hostId(ethPkt.getDestinationMAC());
                        LevelRule level = getHostLevel(hostid);

                        modsrc = nat(IpAddress.valueOf(iPv4.getSourceAddress()), 1).toOctets();
                        if (IpAddress.valueOf(iPv4.getDestinationAddress()).equals(IpAddress.valueOf("10.0.0.254"))) {
                            //moddst = nat2(IpAddress.valueOf(iPv4.getSourceAddress()), 1).toOctets();
                            moddst = level.level().natByLevel(1).toOctets();
                        }
                        installRule(context, context.inPacket().parsed(), modsrc, moddst, port);

                        if (IpAddress.valueOf(iPv4.getDestinationAddress()).equals(IpAddress.valueOf("10.0.0.254"))) {
                            //iPv4.setDestinationAddress(nat2(IpAddress.valueOf(iPv4.getSourceAddress()), 1).toString());
                            iPv4.setDestinationAddress(level.level().natByLevel(1).toString());
                        }
                        iPv4.setSourceAddress(nat(IpAddress.valueOf(iPv4.getSourceAddress()), 1).toString());
                        iPv4.resetChecksum();

                        ethpkt.setPayload(iPv4);

                        OutboundPacket outboundPacket = new DefaultOutboundPacket(context.inPacket().receivedFrom().deviceId(),
                                                                                  context.treatmentBuilder().setOutput(port).build(),
                                                                                  ByteBuffer.wrap(ethpkt.serialize()));
                        packetService.emit(outboundPacket);
                        context.block();
                        return;
                    }
                    // IPv4 send from host && DST is host, do the next job.
                }
            }

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, context.inPacket().parsed(), null, null,dst.location().port());
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
            installRule(context, context.inPacket().parsed(),null,null, path.src().port());
        }
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

    public MacAddress getGatewayMacByHostId(HostId hostId) {
        LevelRule level = getHostLevel(hostId);
        return level.level().getMac();
    }

    @Override
    public List<HostInfo> getHostInfos() {
        return hostStore.getHostInfos();
    }

    @Override
    public void addHostInfo(HostInfo host) {
        hostStore.addHostInfo(host);
    }

    @Override
    public HostInfo getHostInfo(HostId hostId) {
        return hostStore.getHostInfoById(hostId);
    }

    @Override
    public LevelRule getHostLevel(HostId hostId) {
        return hostStore.getHostLevelById(hostId);
    }

    @Override
    public void removeHostInfo(HostId hostId) {
        hostStore.removeHostInfo(hostId);
    }

    @Override
    public void clearHosts() {
        hostStore.clearHosts();
    }

    @Override
    public Level[] getLevelDef() {
        return Level.values();
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
}
