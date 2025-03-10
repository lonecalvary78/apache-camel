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
/*
 * Camel Api Route test generated by camel-api-component-maven-plugin
 */
package org.apache.camel.component.dhis2;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.dhis2.internal.Dhis2ApiCollection;
import org.apache.camel.component.dhis2.internal.Dhis2GetApiMethod;
import org.apache.camel.processor.aggregate.GroupedBodyAggregationStrategy;
import org.hisp.dhis.api.model.v40_2_2.OrganisationUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for {@link org.apache.camel.component.dhis2.api.Dhis2Get} APIs.
 */
public class Dhis2GetIT extends AbstractDhis2TestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(Dhis2GetIT.class);
    private static final String PATH_PREFIX = Dhis2ApiCollection.getCollection().getApiName(Dhis2GetApiMethod.class).getName();

    @Test
    public void testCollection() {
        final Map<String, Object> headers = new HashMap<>();
        headers.put("CamelDhis2.path", "organisationUnits");
        headers.put("CamelDhis2.arrayName", "organisationUnits");
        headers.put("CamelDhis2.paging", true);
        headers.put("CamelDhis2.fields", null);
        headers.put("CamelDhis2.filter", null);
        headers.put("CamelDhis2.queryParams", new HashMap<>());

        final List<OrganisationUnit> result = requestBodyAndHeaders("direct://COLLECTION", null, headers);

        assertTrue(result.size() >= 2);
        LOG.debug("collection: {}", result);
    }

    @Test
    public void testResource() {
        final Map<String, Object> headers = new HashMap<>();
        headers.put("CamelDhis2.path", String.format("organisationUnits/%s", Environment.ORG_UNIT_ID_UNDER_TEST));
        headers.put("CamelDhis2.fields", null);
        headers.put("CamelDhis2.filter", null);
        headers.put("CamelDhis2.queryParams", null);

        final java.io.InputStream result = requestBodyAndHeaders("direct://RESOURCE", null, headers);

        assertNotNull(result, "resource result");
        LOG.debug("Result: {}", result);
    }

    @Override
    protected RouteBuilder createRouteBuilder() throws Exception {
        return new RouteBuilder() {
            public void configure() {
                // test route for collection
                from("direct://COLLECTION")
                        .to("dhis2://" + PATH_PREFIX + "/collection?paging=false")
                        .split().body().aggregationStrategy(new GroupedBodyAggregationStrategy())
                        .convertBodyTo(OrganisationUnit.class);

                // test route for resource
                from("direct://RESOURCE")
                        .to("dhis2://" + PATH_PREFIX + "/resource");
            }
        };
    }
}
