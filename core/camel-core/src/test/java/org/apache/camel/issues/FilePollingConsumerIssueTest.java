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
package org.apache.camel.issues;

import java.util.UUID;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.camel.PollingConsumer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class FilePollingConsumerIssueTest extends ContextTestSupport {
    private static final String TEST_FILE_NAME = "hello" + UUID.randomUUID() + ".txt";

    @Test
    public void testFilePollingConsumer() throws Exception {
        template.sendBodyAndHeader(fileUri(), "Hello World", Exchange.FILE_NAME, TEST_FILE_NAME);

        Endpoint endpoint = context.getEndpoint(fileUri("?initialDelay=0&delay=10&fileName=" + TEST_FILE_NAME));
        PollingConsumer consumer = endpoint.createPollingConsumer();
        consumer.start();
        Exchange exchange = consumer.receive(5000);
        assertNotNull(exchange);

        assertEquals(TEST_FILE_NAME, exchange.getIn().getHeader(Exchange.FILE_NAME, String.class));
        assertEquals("Hello World", exchange.getIn().getBody(String.class));

        consumer.stop();
    }
}
