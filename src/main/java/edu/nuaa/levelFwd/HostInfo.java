package edu.nuaa.levelFwd;

import com.google.common.base.MoreObjects;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.core.IdGenerator;
import org.onosproject.net.DeviceId;

import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;
import static jersey.repackaged.com.google.common.base.Preconditions.checkState;

/*
 * hosts infomation
 */
public class HostInfo {


    private final HostsId id;

    private final VlanId vlanId;
    private final DeviceId  deviceId;
    private final IpPrefix Ip;
    private final MacAddress srcMAC;

    private LevelRule rule;

    protected static IdGenerator idGenerator;
    private static final Object ID_GENERATOR_LOCK = new Object();

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
    private HostInfo(VlanId vlanId, DeviceId deviceId, IpPrefix Ip, MacAddress srcMAC,
                     LevelRule rule){

        synchronized (ID_GENERATOR_LOCK) {
            checkState(idGenerator != null, "Id generator is not bound.");
            this.id = HostsId.valueOf(idGenerator.getNewId());
        }

        this.vlanId = vlanId;
        this.deviceId = deviceId;
        this.Ip = Ip;
        this.srcMAC = srcMAC;

        this.rule = rule;
    }

    public static Builder builder(){
        return new Builder();
    }

    public static class Builder{

        private VlanId vlanId = null;
        private DeviceId deviceId = null;
        private IpPrefix Ip = null;
        private MacAddress srcMAC = null;
        private LevelRule rule = null;

        private Builder() {
            // Hide constructor
        }

        public Builder vlanId(VlanId vlanId){
            this.vlanId = vlanId;
            return this;
        }

        public Builder deviceId(DeviceId deviceId){
            this.deviceId = deviceId;
            return this;
        }

        public Builder Ip(IpPrefix Ip){
            this.Ip = Ip;
            return this;
        }

        public Builder srcMAC(MacAddress srcMAC){
            this.srcMAC = srcMAC;
            return this;
        }

        public Builder rule(LevelRule rule){
            this.rule = rule;
            return this;
        }

        public HostInfo build(){
            checkState(vlanId != null && deviceId != null && Ip != null && srcMAC != null,"Host infomation must be obained");
          if (rule == null){
                rule.reSetLevel();
            }
            return new HostInfo(vlanId, deviceId, Ip, srcMAC, rule);
        }
    }

    public static void bindIdGenerator(IdGenerator newIdGenerator) {
        synchronized (ID_GENERATOR_LOCK) {
            checkState(idGenerator == null, "Id generator is already bound.");
            idGenerator = checkNotNull(newIdGenerator);
        }
    }

    public HostsId id(){
        return this.id;
    }

    public VlanId vlanId(){
        return this.vlanId;
    }

    public DeviceId deviceId(){
        return this.deviceId;
    }

    public IpPrefix Ip(){
        return this.Ip;
    }

    public MacAddress srcMAC(){
        return this.srcMAC;
    }

    public LevelRule rule() {
        return rule;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id.fingerprint(), vlanId, deviceId, Ip, srcMAC, rule);
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
                .add("rule", rule)
                .toString();
    }

}
