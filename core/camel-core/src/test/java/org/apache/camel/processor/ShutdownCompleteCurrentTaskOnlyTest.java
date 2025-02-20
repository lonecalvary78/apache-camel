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
import org.apache.camel.ShutdownRunningTask;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisabledOnOs(architectures = { "s390x" },
              disabledReason = "This test does not run reliably on s390x (see CAMEL-21438)")
public class ShutdownCompleteCurrentTaskOnlyTest extends ContextTestSupport {

    public static final String FILE_QUERY = "?initialDelay=0&delay=10&synchronous=true";

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        String url = fileUri(FILE_QUERY);
        template.sendBodyAndHeader(url, "A", Exchange.FILE_NAME, "a.txt");
        template.sendBodyAndHeader(url, "B", Exchange.FILE_NAME, "b.txt");
        template.sendBodyAndHeader(url, "C", Exchange.FILE_NAME, "c.txt");
        template.sendBodyAndHeader(url, "D", Exchange.FILE_NAME, "d.txt");
        template.sendBodyAndHeader(url, "E", Exchange.FILE_NAME, "e.txt");
    }

    @Test
    public void testShutdownCompleteCurrentTaskOnly() throws Exception {
        // give it 20 seconds to shutdown
        context.getShutdownStrategy().setTimeout(20);

        MockEndpoint bar = getMockEndpoint("mock:bar");
        bar.expectedMinimumMessageCount(1);

        assertMockEndpointsSatisfied();

        // shutdown during processing
        context.stop();

        // should NOT route all 5
        assertTrue(bar.getReceivedCounter() < 5, "Should NOT complete all messages, was: " + bar.getReceivedCounter());
    }

    @Override
    protected RouteBuilder createRouteBuilder() {
        String url = fileUri(FILE_QUERY);
        return new RouteBuilder() {
            @Override
            public void configure() {
                from(url)
                        // let it complete only current task so we shutdown faster
                        .shutdownRunningTask(ShutdownRunningTask.CompleteCurrentTaskOnly).delay(1000).syncDelayed()
                        .to("seda:foo");

                from("seda:foo").routeId("route2").to("mock:bar");
            }
        };
    }

}
