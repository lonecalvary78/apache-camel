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
package org.apache.camel.processor.aggregator;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.processor.BodyInAggregatingStrategy;
import org.junit.jupiter.api.Test;

public class AggregateSimpleTimeoutTest extends ContextTestSupport {

    @Test
    public void testAggregateSimpleTimeout() throws Exception {
        getMockEndpoint("mock:aggregated").expectedBodiesReceived("A+B+C");

        template.sendBodyAndHeader("direct:start", "A", "id", 123);
        template.sendBodyAndHeader("direct:start", "B", "id", 123);
        template.sendBodyAndHeader("direct:start", "C", "id", 123);

        assertMockEndpointsSatisfied();
    }

    @Override
    protected RouteBuilder createRouteBuilder() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                // START SNIPPET: e1
                from("direct:start")
                        // aggregate all exchanges correlated by the id header.
                        // Aggregate them using the BodyInAggregatingStrategy
                        // strategy which
                        // and after 0.1 second of inactivity them timeout and
                        // complete the aggregation
                        // and send it to mock:aggregated
                        .aggregate(header("id"), new BodyInAggregatingStrategy()).completionTimeout(100)
                        .completionTimeoutCheckerInterval(10).to("mock:aggregated");
                // END SNIPPET: e1
            }
        };
    }
}
