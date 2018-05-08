package edu.nuaa.levelFwd.impl;

import org.onlab.packet.IpAddress;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.neighbour.NeighbourMessageContext;
import org.onosproject.net.neighbour.NeighbourMessageHandler;

import java.util.Set;

import static org.onlab.packet.VlanId.vlanId;
import static org.onosproject.net.HostId.hostId;

public class InternalNeighbourMessageHandler implements NeighbourMessageHandler {
    private LevelManager levelManager;

    public InternalNeighbourMessageHandler(LevelManager manager) {
        levelManager = manager;
    }

    @Override
    public void handleMessage(NeighbourMessageContext context, HostService hostService) {
        switch (context.type()) {
            case REPLY:

                // if middlebox then change dst and src.
//                if (levelManager.isMacInGateways(context.srcMac())) {
//                    Host h = hostService.getHost(hostId())
//                }
                Host h = hostService.getHost(hostId(context.packet().getDestinationMAC(),
                                                    vlanId(context.packet().getVlanID())));
                if (h == null) {
                    context.flood();
                } else {
                    context.forward(h.location());
                }
                break;
            case REQUEST:
                // if dst is middlebox then reply specific mac
                if (context.target().equals(IpAddress.valueOf("10.0.0.254"))) {
                    HostId host = HostId.hostId(context.srcMac(), context.vlan());
                    context.reply(levelManager.getGatewayMacByHostId(host));
                }

                IpAddress target = context.target();

                // if dst is host then reply specfic mac
                if (levelManager.isIpInSpecial(context.target())) {
                    target = levelManager.recoverIpToNormal(context.target());
                }

                // See if we have the target host in the host store
                Set<Host> hosts = hostService.getHostsByIp(target);

                Host dst = null;
                Host src = hostService.getHost(hostId(context.srcMac(), context.vlan()));

                for (Host host : hosts) {
                    if (host.vlan().equals(context.vlan())) {
                        dst = host;
                        break;
                    }
                }

                if (src != null && dst != null) {
                    // We know the target host so we can respond
                    context.reply(dst.mac());
                    return;
                }

                // The request couldn't be resolved.
                // Flood the request on all ports except the incoming port.
                context.flood();
                break;
            default:
                break;
        }
    }
}
