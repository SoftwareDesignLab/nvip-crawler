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

import static junit.framework.TestCase.*;

public class VeritasParserTest extends AbstractParserTest {

    VeritasParser parser = new VeritasParser();

    // NO CVE on page
    @Test
    public void testVeritasNone() {
        String html = safeReadHtml("src/test/resources/test-veritas-none.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.veritas.com/content/support/en_US/security/VTS22-017",
                html
        );
        assertEquals(0, list.size());
    }

    // Single CVE on page
    @Test
    public void testVeritasSingle() {
        String html = safeReadHtml("src/test/resources/test-veritas-single.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.veritas.com/content/support/en_US/security/VTS22-015",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-45461", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("OS Command Injection vulnerability affecting the NetBackup Java Admin Console"));
        assertEquals("2022-11-15 00:00:00", vuln.getPublishDateString());
        assertEquals("2022-11-18 00:00:00", vuln.getLastModifiedDateString());
    }

    // Multiple CVE on page
    @Test
    public void testVeritasMultiple() {
        String html = safeReadHtml("src/test/resources/test-veritas-multiple.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.veritas.com/content/support/en_US/security/VTS22-013",
                html
        );
        assertEquals(2, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-42301");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Veritas has addressed vulnerabilities affecting NetBackup Primary and Media "));
        assertEquals("2022-09-01 00:00:00", vuln.getPublishDateString());
        assertEquals("2022-09-01 00:00:00", vuln.getLastModifiedDateString());
    }
}
