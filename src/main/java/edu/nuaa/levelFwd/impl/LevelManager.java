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

import edu.nuaa.levelFwd.HostInfo;
import edu.nuaa.levelFwd.HostStore;
import edu.nuaa.levelFwd.HostsId;
import edu.nuaa.levelFwd.LevelService;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.IdGenerator;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.List;

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
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostStore hostStore;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private HostListener hostListener = new InternalHostListener();
//    private PacketProcessor processor = new ReactivePacketProcessor();
    private PacketProcessor processor = new InternalPacketListener();
    private IdGenerator idGenerator;

    private class InternalHostListener implements HostListener {

        @Override
        public void event(HostEvent event) {
            if (event.type() == HostEvent.Type.HOST_ADDED){
                HostInfo.Builder builder = HostInfo.builder();

                builder.vlanId(event.subject().vlan());
                builder.deviceId(event.subject().location().deviceId());
                builder.Ip(event.subject().location().ipElementId().ipAddress().toIpPrefix());
                builder.srcMAC(event.subject().mac());
                HostInfo new_host = builder.build();
                addHostInfo(new_host);

            }
        }
    }

    @Activate
    protected void activate(ComponentContext context) {
        appId = coreService.registerApplication("edu.nuaa.levelFwd");

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchArpTpa(Ip4Address.valueOf("10.0.0.254"))
                .build();

        packetService.addProcessor(processor, PacketProcessor.director(1));

        hostService.addListener(hostListener);

        idGenerator = coreService.getIdGenerator("host-ids");
        HostInfo.bindIdGenerator(idGenerator);

        log.info("Started");
    }

    private class InternalPacketListener implements PacketProcessor {

        @Override
        public void process(PacketContext context) {

            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {

                ARP arp = (ARP) ethPkt.getPayload();

                log.info(arp.toString());
                if (IpAddress.valueOf(IpAddress.Version.INET, arp.getTargetProtocolAddress()).getIp4Address()
                        .equals(IpAddress.valueOf("10.0.0.254"))) {
                    log.info(arp.toString());

                    Ethernet resPkt = ARP.buildArpReply(Ip4Address.valueOf("10.0.0.254"), MacAddress.valueOf("11:22:33:44:55:66"), ethPkt);

                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            .setOutput(context.inPacket().receivedFrom().port())
                            .build();

                    OutboundPacket response = new DefaultOutboundPacket(context.inPacket().receivedFrom().deviceId(),
                                                                        treatment,
                                                                        ByteBuffer.wrap(resPkt.serialize()));

                    packetService.emit(response);
                }
            }
        }
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    private class ReactivePacketProcessor implements PacketProcessor {

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

            MacAddress macAddress = ethPkt.getSourceMAC();

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (isIpv6Multicast(ethPkt)) {
                return;
            }

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                return;
            }

            // Do not process IPv4 multicast packets, let mfwd handle them
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (id.mac().isMulticast()) {
                    return;
                }
            }

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                return;
            }

        }
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    @Override
    public List<HostInfo> getHostInfos(){
        return hostStore.getHostInfos();
    }

    @Override
    public void addHostInfo(HostInfo host){
        hostStore.addHostInfo(host);
    }

    /**
     * Gets an existing Host infomations.
     */
    @Override
    public HostInfo getHostInfo(HostsId hostsId){
        return hostStore.getHostInfoById(hostsId);
    }

    /**
     * Removes an existing Host infomations by host id.
     */
    @Override
    public void removeHostInfo(HostsId hostsId){
        hostStore.removeHostInfo((hostsId));
    }

    /**
     * Clear all Host infomations and reset.
     */
    @Override
    public void clearHosts(){
        hostStore.clearHosts();
    }
}
