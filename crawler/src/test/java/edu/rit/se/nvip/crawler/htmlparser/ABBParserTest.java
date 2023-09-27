package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class ABBParserTest extends AbstractParserTest {

    ABBParser parser = new ABBParser();

    @Test
    public void testABBDownloadAndParse() {
        String html = safeReadHtml("src/test/resources/test-abb.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://search.abb.com/library/Download.aspx?DocumentID=7PAA007893&LanguageCode=en&DocumentPartId=&Action=Launch",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-0580", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("An attacker who successfully exploited this vulnerability could gain access to the protected application"));
        assertEquals("2023-03-27 00:00:00", vuln.getPublishDate());
        assertEquals("2023-03-27 00:00:00", vuln.getLastModifiedDate());
    }
}
