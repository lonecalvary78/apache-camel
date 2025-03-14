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
package org.apache.camel.component.git.producer;

import java.io.File;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.git.GitConstants;
import org.apache.camel.component.git.GitTestSupport;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.Status;
import org.eclipse.jgit.lib.Repository;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GitRemoteProducerTest extends GitTestSupport {

    @Disabled("Require a remote git repository")
    @Test
    public void pushTest() throws Exception {

        Repository repository = getTestRepository();

        File fileToAdd = new File(getGitDir(), filenameToAdd);
        fileToAdd.createNewFile();

        template.send("direct:add", new Processor() {
            @Override
            public void process(Exchange exchange) {
                exchange.getIn().setHeader(GitConstants.GIT_FILE_NAME, filenameToAdd);
            }
        });
        File gitDir = new File(getGitDir(), ".git");
        assertEquals(true, gitDir.exists());

        Status status = new Git(repository).status().call();
        assertTrue(status.getAdded().contains(filenameToAdd));

        template.send("direct:commit", new Processor() {
            @Override
            public void process(Exchange exchange) {
                exchange.getIn().setHeader(GitConstants.GIT_COMMIT_MESSAGE, commitMessage);
            }
        });

        template.requestBody("direct:push", "", Iterable.class);

        repository.close();
    }

    @Override
    protected RouteBuilder createRouteBuilder() throws Exception {
        // force create git repo before routes
        getTestRepository();
        final String dir = getGitDir().getPath();
        return new RouteBuilder() {
            @Override
            public void configure() {
                from("direct:add").to("git://" + dir + "?operation=add");
                from("direct:commit").to("git://" + dir + "?operation=commit");
                from("direct:push")
                        .to("git://" + dir + "?operation=push&remotePath=remoteURL&username=xxx&password=xxx");
            }
        };
    }

}
