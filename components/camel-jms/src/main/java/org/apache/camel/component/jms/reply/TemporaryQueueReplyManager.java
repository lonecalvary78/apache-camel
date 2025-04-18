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
package org.apache.camel.component.jms.reply;

import java.util.concurrent.atomic.AtomicBoolean;

import jakarta.jms.Destination;
import jakarta.jms.ExceptionListener;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.Session;
import jakarta.jms.TemporaryQueue;

import org.apache.camel.AsyncCallback;
import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.NonManagedService;
import org.apache.camel.component.jms.ConsumerType;
import org.apache.camel.component.jms.DefaultJmsMessageListenerContainer;
import org.apache.camel.component.jms.DefaultSpringErrorHandler;
import org.apache.camel.component.jms.SimpleJmsMessageListenerContainer;
import org.apache.camel.component.jms.TemporaryQueueResolver;
import org.apache.camel.support.service.ServiceHelper;
import org.apache.camel.support.service.ServiceSupport;
import org.springframework.jms.listener.AbstractMessageListenerContainer;
import org.springframework.jms.listener.DefaultMessageListenerContainer;
import org.springframework.jms.support.destination.DestinationResolver;

/**
 * A {@link ReplyManager} when using temporary queues.
 */
public class TemporaryQueueReplyManager extends ReplyManagerSupport {

    final TemporaryReplyQueueDestinationResolver destinationResolver;

    public TemporaryQueueReplyManager(CamelContext camelContext, TemporaryQueueResolver resolver) {
        super(camelContext);
        this.destinationResolver = new TemporaryReplyQueueDestinationResolver(resolver);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();
        ServiceHelper.stopService(destinationResolver);
    }

    @Override
    protected ReplyHandler createReplyHandler(
            ReplyManager replyManager, Exchange exchange, AsyncCallback callback,
            String originalCorrelationId, String correlationId, long requestTimeout) {
        return new TemporaryQueueReplyHandler(this, exchange, callback, originalCorrelationId, correlationId, requestTimeout);
    }

    @Override
    public void updateCorrelationId(String correlationId, String newCorrelationId, long requestTimeout) {
        log.trace("Updated provisional correlationId [{}] to expected correlationId [{}]", correlationId, newCorrelationId);

        ReplyHandler handler = correlation.remove(correlationId);
        if (handler != null) {
            correlation.put(newCorrelationId, handler, requestTimeout);
        }
    }

    @Override
    protected void handleReplyMessage(String correlationID, Message message, Session session) {
        ReplyHandler handler = correlation.remove(correlationID);
        if (handler == null && endpoint.isUseMessageIDAsCorrelationID()) {
            handler = waitForProvisionCorrelationToBeUpdated(correlationID, message);
        }

        if (handler != null) {
            handler.onReply(correlationID, message, session);
        } else {
            // we could not correlate the received reply message to a matching request and therefore
            // we cannot continue routing the unknown message
            // log warn and then ignore the message
            log.warn("Reply received for unknown correlationID [{}]. The message will be ignored: {}", correlationID, message);
        }
    }

    @Override
    public void setReplyToSelectorHeader(org.apache.camel.Message camelMessage, Message jmsMessage) throws JMSException {
        // noop
    }

    @Override
    protected AbstractMessageListenerContainer createListenerContainer() throws Exception {
        if (endpoint.getConfiguration().getReplyToConsumerType() == ConsumerType.Default) {
            return createDefaultListenerContainer();
        } else if (endpoint.getConfiguration().getReplyToConsumerType() == ConsumerType.Simple) {
            return createSimpleListenerContainer();
        } else {
            return getAbstractMessageListenerContainer(endpoint);
        }
    }

    protected AbstractMessageListenerContainer createDefaultListenerContainer() throws Exception {
        // Use DefaultMessageListenerContainer as it supports reconnects (see CAMEL-3193)
        DefaultMessageListenerContainer answer
                = new DefaultJmsMessageListenerContainer(endpoint, endpoint.isAllowReplyManagerQuickStop());

        answer.setDestinationName("temporary");
        answer.setDestinationResolver(destinationResolver);
        answer.setAutoStartup(true);
        if (endpoint.getMaxMessagesPerTask() >= 0) {
            answer.setMaxMessagesPerTask(endpoint.getMaxMessagesPerTask());
        }
        if (endpoint.getIdleReceivesPerTaskLimit() != 0) {
            answer.setIdleReceivesPerTaskLimit(endpoint.getIdleReceivesPerTaskLimit());
        }
        answer.setIdleConsumerLimit(endpoint.getIdleConsumerLimit());
        answer.setIdleTaskExecutionLimit(endpoint.getIdleTaskExecutionLimit());
        answer.setMessageListener(this);
        answer.setPubSubDomain(false);
        answer.setSubscriptionDurable(false);
        answer.setConcurrentConsumers(endpoint.getReplyToConcurrentConsumers());
        if (endpoint.getReplyToMaxConcurrentConsumers() > 0) {
            answer.setMaxConcurrentConsumers(endpoint.getReplyToMaxConcurrentConsumers());
        }
        answer.setConnectionFactory(endpoint.getConfiguration().getOrCreateConnectionFactory());
        // we use CACHE_CONSUMER by default to cling to the consumer as long as we can, since we can only consume
        // msgs from the JMS Connection that created the temp destination in the first place
        if (endpoint.getReplyToCacheLevelName() != null) {
            if ("CACHE_NONE".equals(endpoint.getReplyToCacheLevelName())) {
                throw new IllegalArgumentException(
                        "ReplyToCacheLevelName cannot be CACHE_NONE when using temporary reply queues. The value must be either CACHE_CONSUMER, or CACHE_SESSION");
            }
            answer.setCacheLevelName(endpoint.getReplyToCacheLevelName());
        } else {
            answer.setCacheLevel(DefaultMessageListenerContainer.CACHE_CONSUMER);
        }
        setupClientId(endpoint, answer);

        // we cannot do request-reply over JMS with transaction
        answer.setSessionTransacted(false);

        // other optional properties
        answer.setExceptionListener(
                new TemporaryReplyQueueExceptionListener(destinationResolver, endpoint.getExceptionListener()));

        if (endpoint.getErrorHandler() != null) {
            answer.setErrorHandler(endpoint.getErrorHandler());
        } else {
            answer.setErrorHandler(new DefaultSpringErrorHandler(
                    endpoint.getCamelContext(), TemporaryQueueReplyManager.class,
                    endpoint.getErrorHandlerLoggingLevel(), endpoint.isErrorHandlerLogStackTrace()));
        }
        if (endpoint.getReceiveTimeout() >= 0) {
            answer.setReceiveTimeout(endpoint.getReceiveTimeout());
        }
        if (endpoint.getRecoveryInterval() >= 0) {
            answer.setRecoveryInterval(endpoint.getRecoveryInterval());
        }
        if (endpoint.getTaskExecutor() != null) {
            if (log.isDebugEnabled()) {
                log.debug("Using custom TaskExecutor: {} on listener container: {}", endpoint.getTaskExecutor(), answer);
            }
            answer.setTaskExecutor(endpoint.getTaskExecutor());
        }

        // setup a bean name which is used by Spring JMS as the thread name
        // use the name of the request destination
        String name = "TemporaryQueueReplyManager[" + endpoint.getDestinationName() + "]";
        answer.setBeanName(name);

        if (answer.getConcurrentConsumers() > 1) {
            // log that we are using concurrent consumers
            log.info("Using {}-{} concurrent consumers on {}",
                    answer.getConcurrentConsumers(), answer.getMaxConcurrentConsumers(), name);
        }
        return answer;
    }

    private AbstractMessageListenerContainer createSimpleListenerContainer() {
        SimpleJmsMessageListenerContainer answer = new SimpleJmsMessageListenerContainer(endpoint);
        answer.setDestinationName("temporary");
        answer.setDestinationResolver(destinationResolver);
        answer.setAutoStartup(true);
        answer.setMessageListener(this);
        answer.setPubSubDomain(false);
        answer.setSubscriptionDurable(false);
        answer.setConcurrentConsumers(endpoint.getReplyToConcurrentConsumers());
        answer.setConnectionFactory(endpoint.getConfiguration().getOrCreateConnectionFactory());
        String clientId = endpoint.getClientId();
        if (clientId != null) {
            clientId += ".CamelReplyManager";
            answer.setClientId(clientId);
        }

        // we cannot do request-reply over JMS with transaction
        answer.setSessionTransacted(false);

        // other optional properties
        answer.setExceptionListener(
                new TemporaryReplyQueueExceptionListener(destinationResolver, endpoint.getExceptionListener()));

        if (endpoint.getErrorHandler() != null) {
            answer.setErrorHandler(endpoint.getErrorHandler());
        } else {
            answer.setErrorHandler(new DefaultSpringErrorHandler(
                    endpoint.getCamelContext(), TemporaryQueueReplyManager.class,
                    endpoint.getErrorHandlerLoggingLevel(), endpoint.isErrorHandlerLogStackTrace()));
        }
        if (endpoint.getTaskExecutor() != null) {
            if (log.isDebugEnabled()) {
                log.debug("Using custom TaskExecutor: {} on listener container: {}", endpoint.getTaskExecutor(), answer);
            }
            answer.setTaskExecutor(endpoint.getTaskExecutor());
        }

        // setup a bean name which is used by Spring JMS as the thread name
        // use the name of the request destination
        String name = "TemporaryQueueReplyManager[" + endpoint.getDestinationName() + "]";
        answer.setBeanName(name);

        if (endpoint.getReplyToConcurrentConsumers() > 1) {
            // log that we are using concurrent consumers
            log.info("Using {} concurrent consumers on {}",
                    endpoint.getReplyToConcurrentConsumers(), name);
        }
        return answer;
    }

    private final class TemporaryReplyQueueExceptionListener implements ExceptionListener {
        private final TemporaryReplyQueueDestinationResolver destResolver;
        private final ExceptionListener delegate;

        private TemporaryReplyQueueExceptionListener(TemporaryReplyQueueDestinationResolver destResolver,
                                                     ExceptionListener delegate) {
            this.destResolver = destResolver;
            this.delegate = delegate;
        }

        @Override
        public void onException(JMSException exception) {
            // capture exceptions, and schedule a refresh of the ReplyTo destination
            String msg
                    = "Exception inside the DMLC for Temporary ReplyTo Queue for destination " + endpoint.getDestinationName()
                      + ", refreshing ReplyTo destination (stacktrace in DEBUG logging level).";
            boolean stopped = camelContext.isStopped();
            if (stopped) {
                // if camel is stopped then an exception can happen during stopping connection to broker
                log.debug(msg);
            } else {
                log.warn(msg);
            }
            if (log.isDebugEnabled()) {
                log.debug(msg, exception);
            }
            if (!stopped) {
                destResolver.scheduleRefresh();
                // serve as a proxy for any exception listener the user may have set explicitly
                if (delegate != null) {
                    delegate.onException(exception);
                }
            }
        }

    }

    private final class TemporaryReplyQueueDestinationResolver extends ServiceSupport
            implements DestinationResolver, NonManagedService {
        private TemporaryQueue queue;
        private final AtomicBoolean refreshWanted = new AtomicBoolean();
        private final TemporaryQueueResolver custom;

        public TemporaryReplyQueueDestinationResolver(TemporaryQueueResolver custom) {
            this.custom = custom;
        }

        @Override
        public Destination resolveDestinationName(Session session, String destinationName, boolean pubSubDomain)
                throws JMSException {
            // use a temporary queue to gather the reply message
            if (queue == null || refreshWanted.get()) {
                refreshWanted.set(false);
                if (custom != null) {
                    if (queue != null) {
                        // delete previous queue
                        try {
                            custom.delete(queue);
                        } catch (Exception e) {
                            // ignore
                        }
                    }
                    queue = custom.createTemporaryQueue(session);
                } else {
                    queue = session.createTemporaryQueue();
                }
                setReplyTo(queue);
                if (log.isDebugEnabled()) {
                    log.debug("Refreshed Temporary ReplyTo Queue. New queue: {}", queue.getQueueName());
                }
            }
            return queue;
        }

        public void scheduleRefresh() {
            refreshWanted.set(true);
            replyTo = null;
        }

        @Override
        protected void doStop() throws Exception {
            if (queue != null) {
                try {
                    if (custom != null) {
                        custom.delete(queue);
                    } else {
                        queue.delete();
                    }
                } catch (Exception e) {
                    // ignore
                }
                queue = null;
            }
        }
    }

}
