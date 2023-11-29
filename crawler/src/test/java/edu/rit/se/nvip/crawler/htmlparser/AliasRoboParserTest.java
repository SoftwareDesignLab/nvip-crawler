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

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AliasRoboParserTest extends AbstractParserTest {

    AliasRoboParser parser = new AliasRoboParser();

    // issue in what looks like JSON obj notation
    @Test
    public void testAliasObj() {
        String html = safeReadHtml("src/test/resources/test-alias-obj.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://github.com/aliasrobotics/RVD/issues/3347",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-24012");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Attacker can arbitrarily craft malicious DDS Participants"));
        assertEquals("2023-02-25 04:55:00", vuln.getPublishDateString());
        assertEquals("2023-02-25 04:55:00", vuln.getLastModifiedDateString());

    }

    // issue in what looks like YAML notation
    @Test
    public void testAlias() {
        String html = safeReadHtml("src/test/resources/test-alias.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://github.com/aliasrobotics/RVD/issues/3337",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2020-10292");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Visual Components (owned by KUKA) is a robotic simulator that allows"));
        assertEquals("2020-11-06 04:26:00", vuln.getPublishDateString());
        assertEquals("2020-11-06 04:26:00", vuln.getLastModifiedDateString());

    }

    // no CVE on page but has the words "CVE" and "vulnerability" in comment
    @Test
    public void testAliasNone() {
        String html = safeReadHtml("src/test/resources/test-alias-no.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://github.com/aliasrobotics/RVD/issues/3343",
                html
        );
        assertEquals(0, list.size());

    }

}
