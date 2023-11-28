package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AnquankeParserTest extends AbstractParserTest {

    AnquankeParser parser = new AnquankeParser();

    @Test
    public void testAnquankeParser() {
        String html = safeReadHtml("src/test/resources/test-anquanke.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.anquanke.com/post/id/210200",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2020-5764");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("安卓MX Player播放器路径穿越和代码执行漏洞"));
        assertEquals("2020-07-10 16:30:16", vuln.getPublishDateString());
        assertEquals("2020-07-10 16:30:16", vuln.getLastModifiedDateString());
    }
}
