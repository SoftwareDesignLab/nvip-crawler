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
        assertEquals("2020-01-09 10:30:00", vuln.getPublishDate());
        assertEquals("2020-01-09 10:30:00", vuln.getLastModifiedDate());
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
        assertEquals("2022-12-15 11:15:00", vuln.getPublishDate());
        assertEquals("2022-12-15 11:15:00", vuln.getLastModifiedDate());
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
