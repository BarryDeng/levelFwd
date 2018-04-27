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

    public void upLevel(){
        int var = this.level.getCode() - 1;
        this.level = Level.getByValue(var);
    }

    public void downLevel(){
        int var = this.level.getCode() + 1;
        this.level = Level.getByValue(var);
    }


    public void addService(String service){
        this.service.add(service);
    }

    public void delService(String service){
        this.service.remove(service);
    }
}