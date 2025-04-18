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
package org.apache.camel.processor.onexception;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.spi.Registry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OnExceptionOccurredProcessorTest extends ContextTestSupport {

    @Override
    protected Registry createCamelRegistry() throws Exception {
        Registry jndi = super.createCamelRegistry();
        jndi.bind("myProcessor", new MyProcessor());
        return jndi;
    }

    @Test
    public void testOnExceptionOccurred() throws Exception {
        getMockEndpoint("mock:dead").expectedMessageCount(1);

        template.sendBody("direct:start", "Hello World");

        assertMockEndpointsSatisfied();

        MyProcessor myProcessor = context.getRegistry().lookupByNameAndType("myProcessor", MyProcessor.class);
        // 1 = first time + 3 redelivery attempts
        assertEquals(1 + 3, myProcessor.getInvoked());
    }

    @Override
    protected RouteBuilder createRouteBuilder() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                MyProcessor myProcessor = context.getRegistry().lookupByNameAndType("myProcessor", MyProcessor.class);

                errorHandler(deadLetterChannel("mock:dead").maximumRedeliveries(3).redeliveryDelay(0)
                        .onExceptionOccurred(myProcessor));

                from("direct:start").routeId("start").to("log:a").to("direct:foo").to("log:b");

                from("direct:foo").routeId("foo").throwException(new IllegalArgumentException("Forced"));
            }
        };
    }

    public static class MyProcessor implements Processor {

        private int invoked;

        @Override
        public void process(Exchange exchange) {
            invoked++;
            String rid = exchange.getProperty(Exchange.FAILURE_ROUTE_ID, String.class);
            assertEquals("foo", rid);
        }

        public int getInvoked() {
            return invoked;
        }
    }

}
