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
import java.time.LocalDate;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseListTest extends AbstractParserTest {

    @Test
    public void testParseListSwift() {
        String html = safeReadHtml("src/test/resources/test-generic_list_parser-swift.html");
        ParseList parser = new ParseList("https://www.swift.org/support/security.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.swift.org/support/security.html",
                html
        );

        assertTrue(list.size() > 9);
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-24666");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("A program using swift-nio-http2 is vulnerable to a denial of service attack"));
    }

    @Test
    public void testParseListNaver() {
        String html = safeReadHtml("src/test/resources/test-generic_list_parser-naver.html");
        ParseList parser = new ParseList("https://cve.naver.com/advisory");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://cve.naver.com/advisory",
                html
        );

        assertTrue(list.size() > 19);
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-24077");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("Naver Cloud Explorer Beta allows the attacker to execute arbitrary code"));
    }

    @Test
    public void testParseListOpenSSL() {
        String html = safeReadHtml("src/test/resources/test-generic_list_parser-openssl.html");
        ParseList parser = new ParseList("https://www.openssl.org/news/vulnerabilities.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.openssl.org/news/vulnerabilities.html",
                html
        );

        assertTrue(list.size() > 190);
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-0465");
        assertNotNull(vuln);
        assertEquals("2023-03-23 00:00:00", vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("Applications that use a non-default option when verifying certificates may be vulnerable "));
    }
}