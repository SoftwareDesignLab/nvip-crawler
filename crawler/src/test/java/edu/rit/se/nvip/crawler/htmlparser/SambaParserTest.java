package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class SambaParserTest extends AbstractParserTest {

    SambaParser parser = new SambaParser();

    @Test
    public void testSambaParser() {
        String html = safeReadHtml("src/test/resources/test-samba.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.samba.org/samba/security/CVE-2022-38023.html",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-38023");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("The weakness on NetLogon Secure channel is that the secure checksum"));
    }
}
