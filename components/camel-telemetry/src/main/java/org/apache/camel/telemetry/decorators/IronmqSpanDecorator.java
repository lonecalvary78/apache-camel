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
package org.apache.camel.telemetry.decorators;

import org.apache.camel.Exchange;

public class IronmqSpanDecorator extends AbstractMessagingSpanDecorator {

    public static final String CAMEL_IRON_MQ_MESSAGE_ID = "CamelIronMQMessageId";

    @Override
    public String getComponent() {
        return "ironmq";
    }

    @Override
    public String getComponentClassName() {
        return "org.apache.camel.component.ironmq.IronMQComponent";
    }

    @Override
    protected String getMessageId(Exchange exchange) {
        return exchange.getIn().getHeader(CAMEL_IRON_MQ_MESSAGE_ID, String.class);
    }

}
