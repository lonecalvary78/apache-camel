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
package org.apache.camel.processor;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.RouteDefinition;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class InlinedProcessorIdTest extends ContextTestSupport {

    @Override
    protected RouteBuilder createRouteBuilder() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                from("direct:start").routeId("foo").to("log:foo").id("log").process(new Processor() {
                    public void process(Exchange exchange) {
                        exchange.getIn().setHeader("foo", 123);
                    }
                }).id("inlined").to("mock:result").id("result");
            }
        };
    }

    @Test
    public void testInlinedProcessorId() throws Exception {
        getMockEndpoint("mock:result").expectedHeaderReceived("foo", 123);

        template.sendBody("direct:start", "Hello World");

        assertMockEndpointsSatisfied();

        // check ids
        RouteDefinition route = context.getRouteDefinition("foo");
        assertEquals("foo", route.getId());

        assertEquals(3, route.getOutputs().size());
        assertEquals("log", route.getOutputs().get(0).getId());
        assertEquals("inlined", route.getOutputs().get(1).getId());
        assertEquals("result", route.getOutputs().get(2).getId());
    }

}
