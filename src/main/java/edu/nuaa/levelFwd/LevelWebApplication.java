package edu.nuaa.levelFwd;

import org.onlab.rest.AbstractWebApplication;

import java.util.Set;

/**
 * Sample REST API web application.
 */
public class LevelWebApplication extends AbstractWebApplication {
    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(LevelWebResource.class);
    }
}
