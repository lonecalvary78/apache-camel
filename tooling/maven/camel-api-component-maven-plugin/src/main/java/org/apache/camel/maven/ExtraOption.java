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
package org.apache.camel.maven;

/**
 * Extra endpoint option to add to generated *EndpointConfiguration
 */
public class ExtraOption {

    private String type;
    private String name;
    private String includeMethods;
    private String description;

    public ExtraOption() {
    }

    public ExtraOption(String type, String name, String includeMethods, String description) {
        this.type = type;
        this.name = name;
        this.includeMethods = includeMethods;
        this.description = description;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public String getIncludeMethods() {
        return includeMethods;
    }

    public void setIncludeMethods(String includeMethods) {
        this.includeMethods = includeMethods;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
