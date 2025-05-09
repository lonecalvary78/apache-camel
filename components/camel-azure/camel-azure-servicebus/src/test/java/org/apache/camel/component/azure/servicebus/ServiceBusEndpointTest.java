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
package org.apache.camel.component.azure.servicebus;

import java.util.HashMap;
import java.util.Map;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.messaging.servicebus.ServiceBusSenderClient;
import org.apache.camel.FailedToCreateProducerException;
import org.apache.camel.ResolveEndpointFailedException;
import org.apache.camel.component.azure.servicebus.client.ServiceBusClientFactory;
import org.apache.camel.test.junit5.CamelTestSupport;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;

class ServiceBusEndpointTest extends CamelTestSupport {

    @Test
    void testCreateWithInvalidData() {
        Exception exception = assertThrows(FailedToCreateProducerException.class, () -> {
            template.sendBody("azure-servicebus:test//?", null);
        });
        assertInstanceOf(IllegalArgumentException.class, exception.getCause());

        exception = assertThrows(ResolveEndpointFailedException.class, () -> {
            template.sendBody("azure-servicebus://?connectionString=test", null);
        });
        assertInstanceOf(IllegalArgumentException.class, exception.getCause());

        // provided credential but no fully qualified namespace
        context.getRegistry().bind("credential", new TokenCredential() {
            @Override
            public Mono<AccessToken> getToken(TokenRequestContext tokenRequestContext) {
                return Mono.empty();
            }
        });

        exception = assertThrows(FailedToCreateProducerException.class, () -> {
            template.sendBody("azure-servicebus:test?tokenCredential=#credential", null);
        });
        assertInstanceOf(IllegalArgumentException.class, exception.getCause());
    }

    @Test
    void testCreateEndpointWithConfig() throws Exception {
        final String uri = "azure-servicebus://testTopicOrQueue";
        final String remaining = "testTopicOrQueue";
        final Map<String, Object> params = new HashMap<>();
        params.put("serviceBusType", ServiceBusType.topic);
        params.put("prefetchCount", 10);
        params.put("connectionString", "testString");
        params.put("binary", "true");

        final ServiceBusEndpoint endpoint
                = (ServiceBusEndpoint) context.getComponent("azure-servicebus", ServiceBusComponent.class)
                        .createEndpoint(uri, remaining, params);

        assertEquals(ServiceBusType.topic, endpoint.getConfiguration().getServiceBusType());
        assertEquals("testTopicOrQueue", endpoint.getConfiguration().getTopicOrQueueName());
        assertEquals(10, endpoint.getConfiguration().getPrefetchCount());
        assertEquals("testString", endpoint.getConfiguration().getConnectionString());
        assertEquals(true, endpoint.getConfiguration().isBinary());
    }

    @Test
    void testCreateEndpointWithConfigAndSession() throws Exception {
        final String uri = "azure-servicebus://testTopicOrQueue";
        final String remaining = "testTopicOrQueue";
        final Map<String, Object> params = new HashMap<>();
        params.put("serviceBusType", ServiceBusType.topic);
        params.put("prefetchCount", 10);
        params.put("connectionString", "testString");
        params.put("binary", "true");
        params.put("sessionId", "session-1");

        final ServiceBusEndpoint endpoint
                = (ServiceBusEndpoint) context.getComponent("azure-servicebus", ServiceBusComponent.class)
                        .createEndpoint(uri, remaining, params);

        assertEquals(ServiceBusType.topic, endpoint.getConfiguration().getServiceBusType());
        assertEquals("testTopicOrQueue", endpoint.getConfiguration().getTopicOrQueueName());
        assertEquals(10, endpoint.getConfiguration().getPrefetchCount());
        assertEquals("testString", endpoint.getConfiguration().getConnectionString());
        assertEquals(true, endpoint.getConfiguration().isBinary());
        assertEquals("session-1", endpoint.getConfiguration().getSessionId());
    }

    @Test
    void testCreateEndpointWithFqns() throws Exception {
        final String uri = "azure-servicebus://testTopicOrQueue";
        final String remaining = "testTopicOrQueue";
        final String fullyQualifiedNamespace = "namespace.servicebus.windows.net";
        final Map<String, Object> params = new HashMap<>();
        params.put("serviceBusType", ServiceBusType.topic);
        params.put("prefetchCount", 10);
        params.put("fullyQualifiedNamespace", fullyQualifiedNamespace);

        final ServiceBusEndpoint endpoint
                = (ServiceBusEndpoint) context.getComponent("azure-servicebus", ServiceBusComponent.class)
                        .createEndpoint(uri, remaining, params);

        assertEquals(ServiceBusType.topic, endpoint.getConfiguration().getServiceBusType());
        assertEquals("testTopicOrQueue", endpoint.getConfiguration().getTopicOrQueueName());
        assertEquals(10, endpoint.getConfiguration().getPrefetchCount());
        assertEquals(fullyQualifiedNamespace, endpoint.getConfiguration().getFullyQualifiedNamespace());
        assertNull(endpoint.getConfiguration().getTokenCredential());
    }

    @Test
    void testCreateEndpointWithFqnsAndCredential() throws Exception {
        final String uri = "azure-servicebus://testTopicOrQueue";
        final String remaining = "testTopicOrQueue";
        final String fullyQualifiedNamespace = "namespace.servicebus.windows.net";
        final TokenCredential credential = new DefaultAzureCredentialBuilder().build();
        final Map<String, Object> params = new HashMap<>();
        params.put("serviceBusType", ServiceBusType.topic);
        params.put("prefetchCount", 10);
        params.put("fullyQualifiedNamespace", fullyQualifiedNamespace);
        params.put("tokenCredential", credential);

        final ServiceBusEndpoint endpoint
                = (ServiceBusEndpoint) context.getComponent("azure-servicebus", ServiceBusComponent.class)
                        .createEndpoint(uri, remaining, params);

        assertEquals(ServiceBusType.topic, endpoint.getConfiguration().getServiceBusType());
        assertEquals("testTopicOrQueue", endpoint.getConfiguration().getTopicOrQueueName());
        assertEquals(10, endpoint.getConfiguration().getPrefetchCount());
        assertEquals(fullyQualifiedNamespace, endpoint.getConfiguration().getFullyQualifiedNamespace());
        assertEquals(credential, endpoint.getConfiguration().getTokenCredential());
    }

    @Test
    void testCreateEndpointWithFqnsAndCredentialFromRegistry() throws Exception {
        final String uri = "azure-servicebus://testTopicOrQueue";
        final String remaining = "testTopicOrQueue";
        final String fullyQualifiedNamespace = "namespace.servicebus.windows.net";
        final TokenCredential credential = new DefaultAzureCredentialBuilder().build();
        final Map<String, Object> params = new HashMap<>();
        context().getRegistry().bind("tokenCredential", credential);
        params.put("serviceBusType", ServiceBusType.topic);
        params.put("prefetchCount", 10);
        params.put("fullyQualifiedNamespace", fullyQualifiedNamespace);

        final ServiceBusEndpoint endpoint
                = (ServiceBusEndpoint) context.getComponent("azure-servicebus", ServiceBusComponent.class)
                        .createEndpoint(uri, remaining, params);

        assertEquals(ServiceBusType.topic, endpoint.getConfiguration().getServiceBusType());
        assertEquals("testTopicOrQueue", endpoint.getConfiguration().getTopicOrQueueName());
        assertEquals(10, endpoint.getConfiguration().getPrefetchCount());
        assertEquals(fullyQualifiedNamespace, endpoint.getConfiguration().getFullyQualifiedNamespace());
        assertEquals(credential, endpoint.getConfiguration().getTokenCredential());
        assertEquals(CredentialType.AZURE_IDENTITY, endpoint.getConfiguration().getCredentialType());
    }

    @Test
    void testCreateEndpointWithAzureIdentity() throws Exception {
        final String uri = "azure-servicebus://testTopicOrQueue";
        final String remaining = "testTopicOrQueue";
        final String fullyQualifiedNamespace = "namespace.servicebus.windows.net";
        final TokenCredential credential = new DefaultAzureCredentialBuilder().build();
        final Map<String, Object> params = new HashMap<>();
        params.put("serviceBusType", ServiceBusType.topic);
        params.put("prefetchCount", 10);
        params.put("fullyQualifiedNamespace", fullyQualifiedNamespace);
        params.put("credentialType", CredentialType.AZURE_IDENTITY);

        final ServiceBusEndpoint endpoint
                = (ServiceBusEndpoint) context.getComponent("azure-servicebus", ServiceBusComponent.class)
                        .createEndpoint(uri, remaining, params);

        assertEquals(ServiceBusType.topic, endpoint.getConfiguration().getServiceBusType());
        assertEquals("testTopicOrQueue", endpoint.getConfiguration().getTopicOrQueueName());
        assertEquals(10, endpoint.getConfiguration().getPrefetchCount());
        assertEquals(fullyQualifiedNamespace, endpoint.getConfiguration().getFullyQualifiedNamespace());
        assertNull(endpoint.getConfiguration().getTokenCredential());
    }

    @Test
    void testCreateBaseServiceBusClientWithNoCredentialType() throws Exception {
        ServiceBusConfiguration configuration = new ServiceBusConfiguration();
        configuration.setConnectionString("Endpoint=sb://camel.apache.org/;SharedAccessKeyName=test;SharedAccessKey=test");
        configuration.setTopicOrQueueName("myQueue");
        ServiceBusClientFactory factory = new ServiceBusClientFactory();
        ServiceBusSenderClient senderClient = factory.createServiceBusSenderClient(configuration);
        assertNotNull(senderClient);
        senderClient.close();
    }
}
