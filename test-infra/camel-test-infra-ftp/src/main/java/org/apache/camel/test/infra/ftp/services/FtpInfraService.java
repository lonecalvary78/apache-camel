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
package org.apache.camel.test.infra.ftp.services;

import java.nio.file.Path;

import org.apache.camel.test.infra.common.services.InfrastructureService;

/**
 * Test infra service for Ftp
 */
public interface FtpInfraService extends InfrastructureService {
    @Deprecated
    // Use port
    int getPort();

    Path getFtpRootDir();

    int port();

    @Deprecated
    // use host
    default String hostname() {
        return "localhost";
    }

    default String host() {
        return "localhost";
    }

    default String username() {
        return "admin";
    }

    default String password() {
        return "admin";
    }

    default String directoryName() {
        return "myTestDirectory";
    }
}
