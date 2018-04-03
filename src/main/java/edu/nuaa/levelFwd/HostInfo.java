package edu.nuaa.levelFwd;

import org.onlab.packet.EthType;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.core.IdGenerator;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.flow.criteria.VlanPcpCriterion;

import static jersey.repackaged.com.google.common.base.Preconditions.checkState;

/*
 * hosts infomation
 */
public class HostInfo {


    private final HostId id;


    private final VlanId vlanId;
    private final DeviceId  deviceId;
    private final Ip4Prefix Ip;
    private final MacAddress srcMAC;

    private final Port inPort;
    private final short srcTPPort;
    private final short dstTPPort;

    private final byte ipProto;
    private final EthType ethType;
    private final VlanPcpCriterion vlanPriority;

    protected static IdGenerator idGenerator;
    private static final Object ID_GENERATOR_LOCK = new Object();

    private HostInfo(){
        this.id = null;
        this.vlanId = null;
        this.deviceId = null;
        this.Ip = null;
        this.srcMAC = null;
        this.inPort = null;
        this.srcTPPort = 0;
        this.dstTPPort = 0;
        this.ipProto = 0;
        this.ethType = null;
        this.vlanPriority = null;
    }

    /*
     * Create a new HostInfo
     */
    private HostInfo(VlanId vlanId, DeviceId deviceId, Ip4Prefix Ip, MacAddress srcMAC,
                     Port inPort, short srcTPPort, short dstTPPort, byte ipProto, EthType ethType,
                     VlanPcpCriterion vlanPriority){

        synchronized (ID_GENERATOR_LOCK) {
            checkState(idGenerator != null, "Id generator is not bound.");
            this.id = HostId.valueOf(idGenerator.getNewId());
        }

        this.vlanId = vlanId;
        this.deviceId = deviceId;
        this.Ip = Ip;
        this.srcMAC = srcMAC;
        this.inPort = inPort;
        this.srcTPPort = srcTPPort;
        this.dstTPPort = dstTPPort;
        this.ipProto = ipProto;
        this.ethType = ethType;
        this.vlanPriority = vlanPriority;
    }


}
