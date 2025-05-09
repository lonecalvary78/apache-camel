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

import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.camel.telemetry.Span;
import org.apache.camel.telemetry.TagConstants;

public class SqlSpanDecorator extends AbstractSpanDecorator {

    public static final String CAMEL_SQL_QUERY = "CamelSqlQuery";

    @Override
    public String getComponent() {
        return "sql";
    }

    @Override
    public String getComponentClassName() {
        return "org.apache.camel.component.sql.SqlComponent";
    }

    @Override
    public void beforeTracingEvent(Span span, Exchange exchange, Endpoint endpoint) {
        super.beforeTracingEvent(span, exchange, endpoint);
        span.setTag(TagConstants.DB_SYSTEM, "sql");

        String query = exchange.getIn().getHeader(CAMEL_SQL_QUERY, String.class);
        if (query != null) {
            span.setTag(TagConstants.DB_STATEMENT, query);
        }
    }

}
