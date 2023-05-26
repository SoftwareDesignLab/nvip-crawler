package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;

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
        assertEquals(current_date, vuln.getPublishDate());
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
        assertEquals(current_date, vuln.getPublishDate());
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
        assertEquals("23 March 2023", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Applications that use a non-default option when verifying certificates may be vulnerable "));
    }
}