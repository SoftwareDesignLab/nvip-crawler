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
import static org.junit.Assert.*;

public class AsustorParserTest extends AbstractParserTest {

    AsustorParser parser = new AsustorParser();

    @Test
    public void testAsustorParserNone() {
        String html = safeReadHtml("src/test/resources/test-asustor-none.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.asustor.com/security/security_advisory_detail?id=9",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testAsustorParserSingle() {
        String html = safeReadHtml("src/test/resources/test-asustor-single.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.asustor.com/security/security_advisory_detail?id=4",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-0847");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("A flaw was found in the way the \"flags\" member of the new pipe buffer structure was lacking prope"));
        assertEquals("2022-03-11 00:00:00", vuln.getPublishDateString());
        assertEquals("2022-07-07 00:00:00", vuln.getLastModifiedDateString());
    }

    @Test
    public void testAsustorParserMultiple() {
        String html = safeReadHtml("src/test/resources/test-asustor-multiple.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.asustor.com/security/security_advisory_detail?id=20",
                html
        );
        assertEquals(4, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-4304");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE."));
        assertFalse(vuln.getDescription().contains("This could be exploited by an attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service attack."));
        assertEquals("2023-03-31 00:00:00", vuln.getPublishDateString());
        assertEquals("2023-03-31 00:00:00", vuln.getLastModifiedDateString());
    }


}
