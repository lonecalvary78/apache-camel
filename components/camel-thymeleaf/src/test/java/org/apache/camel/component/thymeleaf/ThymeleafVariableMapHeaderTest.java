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
package org.apache.camel.component.thymeleaf;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.junit.jupiter.api.Test;

public class ThymeleafVariableMapHeaderTest extends ThymeleafAbstractBaseTest {

    @Test
    public void testThymeleaf() throws Exception {
        MockEndpoint mock = getMockEndpoint(MOCK_RESULT);
        mock.expectedMessageCount(1);
        mock.message(0).body().contains(THANK_YOU_FOR_YOUR_ORDER);
        mock.message(0).body().endsWith(SPAZZ_TESTING_SERVICE);
        mock.message(0).header(ThymeleafConstants.THYMELEAF_TEMPLATE).isNull();
        mock.message(0).header(ThymeleafConstants.THYMELEAF_VARIABLE_MAP).isNull();
        mock.message(0).header(FIRST_NAME).isNull();

        template.request(DIRECT_START, variableMapHeaderProcessor);

        mock.assertIsSatisfied();
    }

    @Override
    protected RouteBuilder createRouteBuilder() {
        return new RouteBuilder() {

            public void configure() {
                from(DIRECT_START)
                        .setBody(simple(SPAZZ_TESTING_SERVICE))
                        .to("thymeleaf:dontcare?allowTemplateFromHeader=true&templateMode=HTML&resolver=DEFAULT")
                        .to(MOCK_RESULT);
            }
        };
    }

}
