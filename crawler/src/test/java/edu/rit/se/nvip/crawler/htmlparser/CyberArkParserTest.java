package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class CyberArkParserTest extends AbstractParserTest {

    CyberArkRootParser parser = new CyberArkRootParser();

    @Test
    public void testCyberArkRootParser() {
        String html = safeReadHtml("src/test/resources/test-cyberark.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://labs.cyberark.com/cyberark-labs-security-advisories/",
                html
        );
        assertEquals(132, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-23774");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Docker"));
        assertEquals("2022-01-25 00:00:00", vuln.getPublishDate());
        assertEquals("2022-01-25 00:00:00", vuln.getLastModifiedDate());
    }
}
