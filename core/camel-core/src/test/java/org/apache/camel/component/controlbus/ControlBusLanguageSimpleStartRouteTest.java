/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.controlbus;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.builder.RouteBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 */
public class ControlBusLanguageSimpleStartRouteTest extends ContextTestSupport {

    @Test
    public void testControlBusStartStop() throws Exception {
        assertEquals("Stopped", context.getRouteController().getRouteStatus("foo").name());

        // store a pending message
        getMockEndpoint("mock:foo").expectedBodiesReceived("Hello World");
        template.sendBody("seda:foo", "Hello World");

        // start the route using control bus
        template.sendBody("controlbus:language:simple", "${camelContext.getRouteController().startRoute('foo')}");

        assertMockEndpointsSatisfied();

        // now stop the route, using a header
        template.sendBodyAndHeader("controlbus:language:simple", "${camelContext.getRouteController().stopRoute(${header.me})}",
                "me", "foo");

        assertEquals("Stopped", context.getRouteController().getRouteStatus("foo").name());
    }

    @Test
    public void testControlBusStatus() throws Exception {
        assertEquals("Stopped", context.getRouteController().getRouteStatus("foo").name());

        String status = template.requestBody("controlbus:language:simple",
                "${camelContext.getRouteController().getRouteStatus('foo')}", String.class);
        assertEquals("Stopped", status);

        context.getRouteController().startRoute("foo");

        status = template.requestBody("controlbus:language:simple",
                "${camelContext.getRouteController().getRouteStatus('foo')}", String.class);
        assertEquals("Started", status);
    }

    @Override
    protected RouteBuilder createRouteBuilder() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                from("seda:foo").routeId("foo").autoStartup(false).to("mock:foo");
            }
        };
    }
}
