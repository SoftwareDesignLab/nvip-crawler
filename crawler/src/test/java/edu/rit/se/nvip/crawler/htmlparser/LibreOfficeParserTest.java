package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class LibreOfficeParserTest extends AbstractParserTest {

    LibreOfficeParser parser = new LibreOfficeParser();

    @Test
    public void testLibreOfficeParser() {
        String html = safeReadHtml("src/test/resources/test-libreoffice.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.libreoffice.org/about-us/security/advisories/cve-2019-9850/",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2019-9850");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("to block calling LibreLogo from script event handers."));
        assertEquals("2019-08-15 00:00:00", vuln.getPublishDate());
    }

}
