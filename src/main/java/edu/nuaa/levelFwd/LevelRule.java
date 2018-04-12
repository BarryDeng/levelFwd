package edu.nuaa.levelFwd;


import java.util.Set;
import java.util.TreeSet;

/*
 * Level Rule class
 */
public class LevelRule {

    private Action level;
    private Set<String> service = new TreeSet<>();


    public enum Action{
        WHITELIST, RELIABLE, NOMAL, THREAT, BLACKLIST
    }

    private LevelRule() {
        this.level = Action.NOMAL;
        this.service.add("web");
    }

    private LevelRule(Action level, Set<String> service){
        this.level = level;
        this.service = service;
    }


    public Action level(){
        return this.level;
    }

    public Set<String> service() {
        return service;
    }


    public void reSetLevel(){
        this.level = Action.NOMAL;
        this.service.clear();
        this.service.add("web");
    }

    public void upLevel(){
        this.level = Action.RELIABLE;
    }

    public void downLevel(){
        this.level = Action.THREAT;
    }


    public void addService(String service){
        this.service.add(service);
    }

    public void delService(String service){
        this.service.remove(service);
    }
}
