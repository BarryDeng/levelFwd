package edu.nuaa.levelFwd;


import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;

public enum Level {
    WHITELIST(10000,"10.4.0.254", "11:11:11:11:11:11"),
    RELIABLE(10001, "10.5.0.254", "11:11:11:11:11:11"),
    NORMAL(10002, "10.1.0.254", "00:00:00:00:01:00"),
    THREAT(10003, "10.2.0.254", "00:00:00:01:02:00"),
    BLACKLIST(10004, "10.3.0.254", "00:00:00:02:03:00");

    private int code;
    private String ip;
    private String mac;
    private Level(int code, String ip, String mac) {
        this.code = code;
        this.ip = ip;
        this.mac = mac;
    }

    public IpAddress natByLevel(int direction){
        if (direction == 1) {
            return this.getIp();
        } else if (direction == 2){
            return IpAddress.valueOf("10.0.0.254");
        }
        else
            return null;
    }

    public int getCode() {
        return this.code;
    }

    public IpAddress getIp() {
        return IpAddress.valueOf(this.ip);
    }

    public MacAddress getMac(){
        return MacAddress.valueOf(this.mac);
    }

    public void setCode(int code) {
        this.code = code;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public static Level getByValue(int value) {
        if (value > 10004) {
            return Level.BLACKLIST;
        } else if (value < 10000) {
            return Level.WHITELIST;
        } else {
            for (Level level : values()) {
                if (level.getCode() == value) {
                    return level;
                }
            }
        }

        return null;
    }

}