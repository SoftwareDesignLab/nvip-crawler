package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class EatonParserTest extends AbstractParserTest {

    EatonParser parser = new EatonParser();

    @Test
    public void testEatonDownloadAndParse() {
        String html = safeReadHtml("src/test/resources/test-eaton.html");
//        String html = QuickCveCrawler.getContentFromDynamicPage("https://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/wibu-systems-ag-codemeter-vulnerabilities-eaton-security-bulletin.pdf", null);
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/wibu-systems-ag-codemeter-vulnerabilities-eaton-security-bulletin.pdf",
                html
        );
        assertEquals(6, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2020-14509");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("CodeMeter Runtime for protecting the codes and managing the licenses"));
        assertEquals("2020-10-05 00:00:00", vuln.getPublishDate());
        assertEquals("2021-03-04 00:00:00", vuln.getLastModifiedDate());
    }
}
