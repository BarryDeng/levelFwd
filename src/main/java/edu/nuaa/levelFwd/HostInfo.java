package edu.nuaa.levelFwd;

import com.google.common.base.MoreObjects;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.HostId;

import java.util.Objects;

import static org.glassfish.jersey.internal.guava.Preconditions.checkState;

/*
 * hosts information
 */
public class HostInfo {

    private final HostId id;

    private final VlanId vlanId;
    private final DeviceId  deviceId;
    private final IpAddress Ip;
    private final MacAddress srcMAC;

    private LevelRule rule;

    private HostInfo(){
        this.id = null;
        this.vlanId = null;
        this.deviceId = null;
        this.Ip = null;
        this.srcMAC = null;
        this.rule = null;
    }

    /*
     * Create a new HostInfo
     */
    private HostInfo(HostId id, VlanId vlanId, DeviceId deviceId, IpAddress Ip, MacAddress srcMAC,
                     LevelRule rule){

        this.id = id;
        this.vlanId = vlanId;
        this.deviceId = deviceId;
        this.Ip = Ip;
        this.srcMAC = srcMAC;
        this.rule = rule;
    }

    public static Builder builder(){
        return new Builder();
    }

    public HostId id() {
        return this.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, vlanId, deviceId, Ip, srcMAC, rule);
    }

    public VlanId vlanId() {
        return this.vlanId;
    }

    public DeviceId deviceId() {
        return this.deviceId;
    }

    public IpAddress Ip() {
        return this.Ip;
    }

    public MacAddress srcMAC() {
        return this.srcMAC;
    }

    public LevelRule rule() {
        return rule;
    }

    public static class Builder{

        private HostId id = null;
        private VlanId vlanId = null;
        private DeviceId deviceId = null;
        private IpAddress Ip = null;
        private MacAddress srcMAC = null;
        private LevelRule rule = null;

        private Builder() {
            // Hide constructor
        }

        public Builder setHostId(HostId id) {
            this.id = id;
            return this;
        }

        public Builder setVlanId(VlanId vlanId){
            this.vlanId = vlanId;
            return this;
        }

        public Builder setDeviceId(DeviceId deviceId){
            this.deviceId = deviceId;
            return this;
        }

        public Builder setIp(IpAddress Ip) {
            this.Ip = Ip;
            return this;
        }

        public Builder setSrcMAC(MacAddress srcMAC){
            this.srcMAC = srcMAC;
            return this;
        }

        public HostInfo build(){
            checkState(vlanId != null && deviceId != null && Ip != null && srcMAC != null,"Host infomation must be obained");
            if (rule == null) {
                rule = new LevelRule();
            }
            return new HostInfo(id, vlanId, deviceId, Ip, srcMAC, rule);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof HostInfo) {
            HostInfo that = (HostInfo) obj;
            return Objects.equals(id, that.id) &&
                    Objects.equals(vlanId, that.vlanId) &&
                    Objects.equals(deviceId, that.deviceId) &&
                    Objects.equals(Ip, that.Ip) &&
                    Objects.equals(srcMAC, that.srcMAC) &&
                    Objects.equals(rule, that.rule);
        }
        return false;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .omitNullValues()
                .add("id", id)
                .add("vlanId", vlanId)
                .add("deviceId", deviceId)
                .add("Ip", Ip)
                .add("srcMAC", srcMAC)
                .add("rule", rule.toString())
                .toString();
    }
}
