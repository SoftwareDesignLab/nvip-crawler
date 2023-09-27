/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static junit.framework.TestCase.assertEquals;

/**
 * Test Bug Gentoo Parser
 * @author aep7128
 */
public class BugsGentooParserTest extends AbstractParserTest {

    BugsGentooParser parser = new BugsGentooParser();

    /**
     * Test parsing a page with 1 CVE listed
     * @throws IOException
     */
    @Test
    public void testBugsGentooParserSingleCVE() throws IOException {

        String html = FileUtils.readFileToString(new File("src/test/resources/test-bugs-gentoo-single-cve.html"), StandardCharsets.US_ASCII);
        List<RawVulnerability> list = parser.parseWebPage("https://bugs.gentoo.org/600624", html);

        assertEquals(1, list.size());
        RawVulnerability vuln1 = list.get(0);

        assertEquals("CVE-2013-4392", vuln1.getCveId());

        assertEquals("A TOCTOU (time-of-check time-of-use) race condition was found in the way systemd, a system and service manager, used to update file permissions and SELinux security contexts. A local attacker could use this flaw to conduct symbolic link attacks possibly leading to their ability to modify permissions / security context of a path different than originally intended / requested. Issue found by Florian Weimer, Red Hat Product Security Team",
                vuln1.getDescription());
        assertEquals("2016-11-23 20:58:00", vuln1.getPublishDate());
        assertEquals("2019-04-02 05:19:00", vuln1.getLastModifiedDate());

    }

    /**
     * Test parsing a page with more than 1 CVE listed
     * @throws IOException
     */
    @Test
    public void testBugsGentooParserMultiCVE() throws IOException {

        String html = FileUtils.readFileToString(new File("src/test/resources/test-bugs-gentoo-multi-cve.html"), StandardCharsets.US_ASCII);
        List<RawVulnerability> list = parser.parseWebPage("https://bugs.gentoo.org/890865", html);

        assertEquals(2, list.size());

        RawVulnerability vuln1 = list.get(0);
        RawVulnerability vuln2 = list.get(1);

        assertEquals("CVE-2023-22496", vuln1.getCveId());
        assertEquals("CVE-2023-22497", vuln2.getCveId());

        assertEquals("Netdata is an open source option for real-time infrastructure monitoring and troubleshooting. An attacker with the ability to establish a streaming connection can execute arbitrary commands on the targeted Netdata agent. When an alert is triggered, the function `health_alarm_execute` is called. This function performs different checks and then enqueues a command by calling `spawn_enq_cmd`. This command is populated with several arguments that are not sanitized. One of them is the `registry_hostname` of the node for which the alert is raised. By providing a specially crafted `registry_hostname` as part of the health data that is streamed to a Netdata (parent) agent, an attacker can execute arbitrary commands at the remote host as a side-effect of the raised alert. Note that the commands are executed as the user running the Netdata Agent. This user is usually named `netdata`. The ability to run arbitrary commands may allow an attacker to escalate privileges by escalating other vulnerabilities in the system, as that user. The problem has been fixed in: Netdata agent v1.37 (stable) and Netdata agent v1.36.0-409 (nightly). As a workaround, streaming is not enabled by default. If you have previously enabled this, it can be disabled. Limiting access to the port on the recipient Agent to trusted child connections may mitigate the impact of this vulnerability.",
                vuln1.getDescription());
        assertEquals("Netdata is an open source option for real-time infrastructure monitoring and troubleshooting. Each Netdata Agent has an automatically generated MACHINE GUID. It is generated when the agent first starts and it is saved to disk, so that it will persist across restarts and reboots. Anyone who has access to a Netdata Agent has access to its MACHINE_GUID. Streaming is a feature that allows a Netdata Agent to act as parent for other Netdata Agents (children), offloading children from various functions (increased data retention, ML, health monitoring, etc) that can now be handled by the parent Agent. Configuration is done via `stream.conf`. On the parent side, users configure in `stream.conf` an API key (any random UUID can do) to provide common configuration for all children using this API key and per MACHINE GUID configuration to customize the configuration for each child. The way this was implemented, allowed an attacker to use a valid MACHINE_GUID as an API key. This affects all users who expose their Netdata Agents (children) to non-trusted users and they also expose to the same users Netdata Agent parents that aggregate data from all these children. The problem has been fixed in: Netdata agent v1.37 (stable) and Netdata agent v1.36.0-409 (nightly). As a workaround, do not enable streaming by default. If you have previously enabled this, it can be disabled. Limiting access to the port on the recipient Agent to trusted child connections may mitigate the impact of this vulnerability.",
                vuln2.getDescription());
        assertEquals("2023-01-15 04:09:00", vuln1.getPublishDate());
        assertEquals("2023-01-15 04:09:00", vuln1.getLastModifiedDate());
    }



}
