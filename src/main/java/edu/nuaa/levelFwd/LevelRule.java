package edu.nuaa.levelFwd;


import org.onlab.packet.MacAddress;

import java.util.Set;
import java.util.TreeSet;

/*
 * Level Rule class
 */
public class LevelRule {

    private Level level;
    private Set<String> service = new TreeSet<>();


    public LevelRule() {
        this.level = Level.NORMAL;
        this.service.add("web");
    }

    public LevelRule(Level level, Set<String> service) {
        this.level = level;
        this.service = service;
    }

    public void resetLevel() {
        this.level = Level.NORMAL;
        this.service.clear();
        this.service.add("web");
    }

    public Level level(){
        return this.level;
    }

    public Set<String> service() {
        return service;
    }


    public enum Level {
        WHITELIST(10000, "11:11:11:11:11:11"),
        RELIABLE(10001, "22:22:22:22:22:22"),
        NORMAL(10002, "33:33:33:33:33:33"),
        THREAT(10003, "44:44:44:44:44:44"),
        BLACKLIST(10004, "55:55:55:55:55:55");

        private int code;
        private String MAC;
        private Level(int code, String mac) {
            this.code = code;
            this.MAC = mac;
        }

        public int getCode() {
            return code;
        }

        public String getMAC() {
            return MAC;
        }

        public void setCode(int code) {
            this.code = code;
        }

        public void setMAC(String MAC) {
            this.MAC = MAC;
        }

        public static Level getByValue(int value) {
            for (Level level : values()) {
                if (level.getCode() == value) {
                    return level;
                }
            }
            return null;
        }
    }

    public void upLevel(){
        int var = this.level.code - 1;
        this.level = Level.getByValue(var);
    }

    public void downLevel(){
        int var = this.level.code + 1;
        this.level = Level.getByValue(var);
    }


    public void addService(String service){
        this.service.add(service);
    }

    public void delService(String service){
        this.service.remove(service);
    }
}
