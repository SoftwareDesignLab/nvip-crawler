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

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


public class AcronisParserTest extends AbstractParserTest {

    AcronisParser parser = new AcronisParser();

    // Single CVE above title
    @Test
    public void testAcronisSingle() {
        String html = safeReadHtml("src/test/resources/test-acronis-1.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://security-advisory.acronis.com/advisories/SEC-4092",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-3405", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("Code execution and sensitive information disclosure due"));
        assertEquals("2022-11-17 00:00:00", vuln.getPublishDate());
        assertEquals("2023-03-09 00:00:00", vuln.getLastModifiedDate());
    }

    // Multiple CVE, nothing above title, located in description
    @Test
    public void testAcronisMultiple() {
        String html = safeReadHtml("src/test/resources/test-acronis-2.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://security-advisory.acronis.com/advisories/SEC-5299",
                html
        );
        assertEquals(2, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-3602");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("OpenSSL project team released a security advisory"));
        assertEquals("2022-11-01 00:00:00", vuln.getPublishDate());
        assertEquals("2022-11-01 00:00:00", vuln.getLastModifiedDate());
    }

}
