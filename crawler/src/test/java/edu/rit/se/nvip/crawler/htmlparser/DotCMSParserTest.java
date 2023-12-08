/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
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

public class DotCMSParserTest extends AbstractParserTest {

    DotCMSParser parser = new DotCMSParser();

    // CVE: (link)
    @Test
    public void testDotCMSParser1() {
        String html = safeReadHtml("src/test/resources/test-dotcms1.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dotcms.com/security/SI-54",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2020-6754");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("dotCMS fails to normalize the URI string when checking if a user should have access"));
        assertEquals("2020-01-09 10:30:00", vuln.getPublishDateString());
        assertEquals("2020-01-09 10:30:00", vuln.getLastModifiedDateString());
    }

    // CVE standalone id found in references
    @Test
    public void testDotCMSParser2() {
        String html = safeReadHtml("src/test/resources/test-dotcms2.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dotcms.com/security/SI-67",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-45783");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("An authenticated directory traversal vulnerability in dotCMS API can lead to RCE"));
        assertEquals("2022-12-15 11:15:00", vuln.getPublishDateString());
        assertEquals("2022-12-15 11:15:00", vuln.getLastModifiedDateString());
    }

    // no CVE referenced on page
    @Test
    public void testDotCMSParserNone() {
        String html = safeReadHtml("src/test/resources/test-dotcms-none.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dotcms.com/security/SI-53",
                html
        );
        assertEquals(0, list.size());
    }

}
