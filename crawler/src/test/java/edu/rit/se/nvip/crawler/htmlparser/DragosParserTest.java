package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class DragosParserTest extends AbstractParserTest {

    DragosParser parser = new DragosParser();

    // test a dragos page where there are no CVE IDs available
    @Test
    public void testDragosNA() {
        String html = safeReadHtml("src/test/resources/test-dragos-na.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dragos.com/advisory/yokogawa-centum-vp-dcs-his/",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testDragosMultiple() {
        String html = safeReadHtml("src/test/resources/test-dragos-mult.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dragos.com/advisory/automation-directs-directlogic-06-plc-c-more-ea9-hmi-and-ecom-ethernet-module/",
                html
        );
        assertEquals(4, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-2006");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Automation Direct’s DirectLogic 06 PLC"));
        assertEquals("2022-05-31 00:00:00", vuln.getPublishDateString());
        assertEquals("2022-05-31 00:00:00", vuln.getLastModifiedDateString());
    }

}
