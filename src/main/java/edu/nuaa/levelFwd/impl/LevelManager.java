/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.nuaa.levelFwd.impl;

import edu.nuaa.levelFwd.HostInfo;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.IdGenerator;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
@Service
public class LevelManager {

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MastershipService mastershipService;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private final HostListener hostListener = new InternalHostListener();
    private IdGenerator idGenerator;


    private class InternalHostListener implements HostListener {


        @Override
        public void event(HostEvent event) {
            if (event.type() == HostEvent.Type.HOST_ADDED){
                HostInfo.Builder builder = HostInfo.builder();

                builder.vlanId(event.subject().vlan());
                builder.deviceId(event.subject().location().deviceId());
                builder.Ip(event.subject().location().ipElementId().ipAddress().toIpPrefix());
                builder.srcMAC(event.subject().mac());
                HostInfo new_host = builder.build();

            }
        }
    }

    @Activate
    protected void activate() {
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        log.info("Stopped");
    }
}
