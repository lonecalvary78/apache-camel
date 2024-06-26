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
package org.apache.camel.xml.io.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlStreamDetectorTest {

    private String readAllFromFile(String filename) throws IOException {
        final URL resource = getClass().getResource(filename);
        assert resource != null : "Cannot open a null resource: " + filename;

        try (final InputStream inputStream = resource.openStream()) {
            final byte[] bytes = inputStream.readAllBytes();
            return new String(bytes);
        }
    }

    @Test
    public void nonExistingDocument() throws IOException {
        XmlStreamDetector detector = new XmlStreamDetector(getClass().getResourceAsStream("non-existing"));
        assertFalse(detector.information().isValid());
    }

    @Test
    public void emptyDocument() throws IOException {
        XmlStreamDetector detector = new XmlStreamDetector(new ByteArrayInputStream(new byte[0]));
        assertFalse(detector.information().isValid());
    }

    @Test
    public void simplestDocument() throws IOException {
        String xml = "<root />";
        XmlStreamDetector detector
                = new XmlStreamDetector(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        XmlStreamInfo info = detector.information();
        assertTrue(info.isValid());
        assertEquals("root", info.getRootElementName());
        assertNull(info.getRootElementNamespace());
    }

    @Test
    public void documentFullOfNamespaces() throws IOException {
        String xml = readAllFromFile("documentFullOfNamespaces.xml");

        XmlStreamDetector detector
                = new XmlStreamDetector(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        XmlStreamInfo info = detector.information();
        assertTrue(info.isValid());
        assertEquals("root", info.getRootElementName());
        assertEquals("urn:camel", info.getRootElementNamespace());

        assertEquals(6, info.getAttributes().size());
        assertEquals("typo", info.getAttributes().get("xmlnS"));
        assertEquals("v1", info.getAttributes().get("a1"));
        assertEquals("v2", info.getAttributes().get("c:a1"));
        assertEquals("v2", info.getAttributes().get("{urn:camel:ns1}a1"));
        assertEquals("v3", info.getAttributes().get("d:a1"));
        assertEquals("v3", info.getAttributes().get("{urn:camel:ns2}a1"));

        assertEquals(3, info.getNamespaces().size());
        assertEquals("urn:camel", info.getNamespaces().get(""));
        assertEquals("urn:camel:ns1", info.getNamespaces().get("c"));
        assertEquals("urn:camel:ns2", info.getNamespaces().get("d"));
    }

    @Test
    public void documentWithModeline() throws IOException {
        String xml = readAllFromFile("documentWithModeline.xml");

        XmlStreamDetector detector
                = new XmlStreamDetector(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        XmlStreamInfo info = detector.information();
        assertTrue(info.isValid());
        assertEquals("routes", info.getRootElementName());
        assertEquals("http://camel.apache.org/schema/spring", info.getRootElementNamespace());

        assertEquals(0, info.getAttributes().size());

        assertEquals(1, info.getNamespaces().size());
        assertEquals("http://camel.apache.org/schema/spring", info.getNamespaces().get(""));

        assertEquals(3, info.getModelines().size());
        assertEquals("camel-k: dependency=mvn:com.i-heart-camel:best-routes-ever:1.0.0", info.getModelines().get(0));
        assertEquals("camel-k: env=HELLO=world", info.getModelines().get(1));
        assertEquals("camel-k: name=MyApplication", info.getModelines().get(2));
    }

    @Test
    public void simpleRoute() throws IOException {
        String xml = readAllFromFile("simpleRoute.xml");

        XmlStreamDetector detector
                = new XmlStreamDetector(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        XmlStreamInfo info = detector.information();
        assertTrue(info.isValid());
        assertEquals("routes", info.getRootElementName());
        assertEquals("http://camel.apache.org/schema/spring", info.getRootElementNamespace());

        assertEquals(2, info.getAttributes().size());
        assertTrue(info.getAttributes().get("xsi:schemaLocation")
                .contains("https://camel.apache.org/schema/spring/camel-spring.xsd"));
        assertTrue(info.getAttributes().get("{http://www.w3.org/2001/XMLSchema-instance}schemaLocation")
                .contains("https://camel.apache.org/schema/spring/camel-spring.xsd"));

        assertEquals(2, info.getNamespaces().size());
        assertEquals("http://camel.apache.org/schema/spring", info.getNamespaces().get(""));
        assertEquals("http://www.w3.org/2001/XMLSchema-instance", info.getNamespaces().get("xsi"));
    }

}
