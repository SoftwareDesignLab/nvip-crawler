package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class ZeroDaysParserTest extends AbstractParserTest {

    ZeroDaysParser parser = new ZeroDaysParser();

    @Test
    public void testZeroDays() {
        String html = safeReadHtml("src/test/resources/test-zeroday.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://cybersecurityworks.com/zerodays/cve-2022-28291-sensitive-information-disclosure-in-tenable-nessus-scanner.html",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-28291", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("An authenticated user with debug privileges can retrieve stored Nessus policy"));
        assertEquals("2022-05-02 00:00:00", vuln.getPublishDateString());
        assertEquals("2022-10-18 00:00:00", vuln.getLastModifiedDateString());
    }

}
