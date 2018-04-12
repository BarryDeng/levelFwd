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

    private LevelRule rule;

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
        this.rule = null;
    }

    /*
     * Create a new HostInfo
     */
    private HostInfo(VlanId vlanId, DeviceId deviceId, Ip4Prefix Ip, MacAddress srcMAC,
                     Port inPort, short srcTPPort, short dstTPPort, byte ipProto, EthType ethType,
                     VlanPcpCriterion vlanPriority, LevelRule rule){

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
        this.rule = rule;
    }


    public static class Builder{

        private VlanId vlanId = null;
        private DeviceId deviceId = null;
        private Ip4Prefix Ip = null;
        private MacAddress srcMAC = null;
        private Port inPort = null;
        private short srcTPPort = 0;
        private short dstTPPort = 0;
        private byte ipProto = 0;
        private EthType ethType = null;
        private VlanPcpCriterion vlanPriority = null;
        private LevelRule rule = null;

        private Builder() {
            // Hide constructor
        }

        public Builder vlanId(VlanId vlanId){
            this.vlanId = vlanId;
            return this;
        }

        public Builder Ip(Ip4Prefix Ip){
            this.Ip = Ip;
            return this;
        }

        public Builder srcMAC(MacAddress srcMAC){
            this.srcMAC = srcMAC;
            return this;
        }

        public Builder inPort(Port inPort){
            this.inPort = inPort;
            return this;
        }

        public Builder srcTPPort(short srcTPPort){
            this.srcTPPort = srcTPPort;
            return this;
        }

        public Builder dstTPPort(short dstTPPort){
            this.dstTPPort = dstTPPort;
            return this;
        }

        public Builder ipProto(byte ipProto){
            this.ipProto = ipProto;
            return this;
        }

        public Builder ethType(EthType ethType){
            this.ethType = ethType;
            return this;
        }

        public Builder vlanPriority(VlanPcpCriterion vlanPriority){
            this.vlanPriority = vlanPriority;
            return this;
        }

        public Builder rule(LevelRule rule){
            this.rule = rule;
            return this;
        }

        public HostInfo build(){
            checkState(vlanId != null && deviceId != null && Ip != null && srcMAC != null,"Host infomation must be obained");
            checkState(inPort != null && srcTPPort != 0 && dstTPPort != 0,  "Port must be accepted");
            checkState(ipProto != 0 && ethType != null && vlanPriority != null,"Host's property cannot be empty");
            if (rule == null){
                rule.reSetLevel();
            }
            return new HostInfo(vlanId, deviceId, Ip, srcMAC, inPort, srcTPPort, dstTPPort, ipProto, ethType, vlanPriority, rule);
        }
    }

    public HostId id(){
        return this.id;
    }

    public VlanId vlanId(){
        return this.vlanId;
    }

    public DeviceId deviceId(){
        return this.deviceId;
    }

    public Ip4Prefix Ip(){
        return this.Ip;
    }

    public MacAddress srcMAC(){
        return this.srcMAC;
    }

    public Port inPort(){
        return this.inPort;
    }

    public short srcTPPort(){
        return this.srcTPPort;
    }

    public short dstTPPort(){
        return this.dstTPPort;
    }

    public EthType ethType() {
        return ethType;
    }

    public VlanPcpCriterion vlanPriority() {
        return vlanPriority;
    }

    public LevelRule rule() {
        return rule;
    }
}
