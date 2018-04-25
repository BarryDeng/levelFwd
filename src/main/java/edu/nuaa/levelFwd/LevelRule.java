package edu.nuaa.levelFwd;


import org.onlab.packet.MacAddress;

import java.util.Set;
import java.util.TreeSet;

/*
 * Level Rule class
 */
public class LevelRule {

    private Action level;
    private Set<String> service = new TreeSet<>();
    private MacAddress middleBox;


    private MacAddress[] middleBoxs = new MacAddress[5];

    public LevelRule() {
        this.level = Action.NORMAL;
        this.service.add("web");
        this.middleBox = middleBoxs[this.level.ordinal()];
    }

    public LevelRule(Action level, Set<String> service) {
        this.level = level;
        this.service = service;
    }

    public void resetLevel() {
        this.level = Action.NORMAL;
        this.service.clear();
        this.service.add("web");
    }


    public Action level(){
        return this.level;
    }

    public Set<String> service() {
        return service;
    }

    public MacAddress middleBox(){
        return this.middleBox;
    }


    public enum Action {
        WHITELIST, RELIABLE, NORMAL, THREAT, BLACKLIST
    }

    public void upLevel(){
        Action var = this.level;
        var = Action.values()[var.ordinal() - 1];
        this.level = var;
        this.middleBox = middleBoxs[this.level.ordinal()];
    }

    public void downLevel(){
        Action var = this.level;
        var = Action.values()[var.ordinal() + 1];
        this.level = var;
        this.middleBox = middleBoxs[this.level.ordinal()];
    }


    public void addService(String service){
        this.service.add(service);
    }

    public void delService(String service){
        this.service.remove(service);
    }
}
