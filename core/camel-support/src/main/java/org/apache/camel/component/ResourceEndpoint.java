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
package org.apache.camel.component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.camel.Component;
import org.apache.camel.api.management.ManagedResource;
import org.apache.camel.api.management.mbean.ManagedResourceEndpointMBean;
import org.apache.camel.spi.Metadata;
import org.apache.camel.spi.UriParam;
import org.apache.camel.spi.UriPath;
import org.apache.camel.support.ProcessorEndpoint;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.util.IOHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A useful base class for endpoints which depend on a resource such as things like Velocity or XQuery based components.
 */
@ManagedResource(description = "Managed ResourceEndpoint")
public abstract class ResourceEndpoint extends ProcessorEndpoint implements ManagedResourceEndpointMBean {
    protected final Logger log = LoggerFactory.getLogger(getClass());
    private volatile byte[] buffer;

    @UriPath(description = "Path to the resource."
                           + " You can prefix with: classpath, file, http, ref, or bean."
                           + " classpath, file and http loads the resource using these protocols (classpath is default)."
                           + " ref will lookup the resource in the registry."
                           + " bean will call a method on a bean to be used as the resource."
                           + " For bean you can specify the method name after dot, eg bean:myBean.myMethod.")
    @Metadata(required = true, supportFileReference = true)
    private String resourceUri;
    @UriParam(defaultValue = "true", description = "Sets whether to use resource content cache or not")
    private boolean contentCache;
    @UriParam(defaultValue = "false", description = "Sets whether the context map should allow access to all details."
                                                    + " By default only the message body and headers can be accessed."
                                                    + " This option can be enabled for full access to the current Exchange and CamelContext."
                                                    + " Doing so impose a potential security risk as this opens access to the full power of CamelContext API.")
    private boolean allowContextMapAll;

    private final Lock lock = new ReentrantLock();

    public ResourceEndpoint() {
    }

    public ResourceEndpoint(String endpointUri, Component component, String resourceUri) {
        super(endpointUri, component);
        this.resourceUri = resourceUri;
    }

    /**
     * Gets the resource as an input stream considering the cache flag as well.
     * <p/>
     * If cache is enabled then the resource content is cached in an internal buffer and this content is returned to
     * avoid loading the resource over and over again.
     *
     * @return             the input stream
     * @throws IOException is thrown if error loading the content of the resource to the local cache buffer
     */
    public InputStream getResourceAsInputStream() throws IOException {
        // try to get the resource input stream
        if (isContentCache()) {
            lock.lock();
            try {
                if (buffer == null) {
                    log.debug("Reading resource: {} into the content cache", resourceUri);
                    try (InputStream is = getResourceAsInputStreamWithoutCache()) {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        IOHelper.copy(IOHelper.buffered(is), bos);
                        buffer = bos.toByteArray();
                    }
                }
            } finally {
                lock.unlock();
            }
            log.debug("Using resource: {} from the content cache", resourceUri);
            return new ByteArrayInputStream(buffer);
        }

        return getResourceAsInputStreamWithoutCache();
    }

    protected InputStream getResourceAsInputStreamWithoutCache() throws IOException {
        return loadResource(resourceUri);
    }

    /**
     * Loads the given resource.
     *
     * @param  uri         uri of the resource.
     * @return             the loaded resource
     * @throws IOException is thrown if resource is not found or cannot be loaded
     */
    protected InputStream loadResource(String uri) throws IOException {
        return ResourceHelper.resolveMandatoryResourceAsInputStream(getCamelContext(), uri);
    }

    @Override
    public boolean isContentCache() {
        return contentCache;
    }

    @Override
    public void clearContentCache() {
        log.debug("Clearing resource: {} from the content cache", resourceUri);
        buffer = null;
    }

    public boolean isContentCacheCleared() {
        return buffer == null;
    }

    /**
     * Whether the context map is limited to only include the message body and headers
     */
    public boolean isAllowContextMapAll() {
        return allowContextMapAll;
    }

    /**
     * Sets whether the context map should allow access to all details. By default only the message body and headers can
     * be accessed. This option can be enabled for full access to the current Exchange and CamelContext. Doing so impose
     * a potential security risk as this opens access to the full power of CamelContext API.
     */
    public void setAllowContextMapAll(boolean allowContextMapAll) {
        this.allowContextMapAll = allowContextMapAll;
    }

    @Override
    public String getCamelId() {
        return getCamelContext().getName();
    }

    @Override
    public String getCamelManagementName() {
        return getCamelContext().getManagementName();
    }

    @Override
    public String getState() {
        return getStatus().name();
    }

    /**
     * Sets whether to use resource content cache or not.
     */
    @Override
    public void setContentCache(boolean contentCache) {
        this.contentCache = contentCache;
    }

    public String getResourceUri() {
        return resourceUri;
    }

    /**
     * Path to the resource.
     * <p/>
     * You can prefix with: classpath, file, http, ref, or bean. classpath, file and http loads the resource using these
     * protocols (classpath is default). ref will lookup the resource in the registry. bean will call a method on a bean
     * to be used as the resource. For bean you can specify the method name after dot, eg bean:myBean.myMethod
     *
     * @param resourceUri the resource path
     */
    public void setResourceUri(String resourceUri) {
        this.resourceUri = resourceUri;
    }
}
