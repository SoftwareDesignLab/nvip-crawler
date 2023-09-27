package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class PandoraFMSParserTest extends AbstractParserTest {

    PandoraFMSRootParser parser = new PandoraFMSRootParser();

    @Test
    public void testPandoraFMSParser() {
        String html = safeReadHtml("src/test/resources/test-pandorafms.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/",
                html
        );
        assertEquals(65, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-24517");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Remote Code Execution via Unrestricted File Upload"));
        assertEquals("2023-02-21 00:00:00", vuln.getPublishDate());
    }
}
