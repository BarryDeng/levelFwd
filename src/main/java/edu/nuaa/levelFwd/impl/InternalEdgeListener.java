package edu.nuaa.levelFwd.impl;

import org.onosproject.net.edge.EdgePortEvent;
import org.onosproject.net.edge.EdgePortListener;

public class InternalEdgeListener implements EdgePortListener {
    private LevelManager manager;

    public InternalEdgeListener(LevelManager manager) {
        this.manager = manager;
    }

    @Override
    public void event(EdgePortEvent event) {
        switch (event.type()) {
            case EDGE_PORT_ADDED:
                manager.addDefault(event.subject());
                break;
            case EDGE_PORT_REMOVED:
                manager.removeDefault(event.subject());
                break;
            default:
                break;
        }
    }
}
