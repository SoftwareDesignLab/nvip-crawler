package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;
import static junit.framework.TestCase.assertEquals;

public class AristaParserTest extends AbstractParserTest {

    @Test
    public void testAristaSingle() {
        String html = safeReadHtml("src/test/resources/test-arista-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.arista.com/en/support/advisories-notices/security-advisory/17022-security-advisory-0083",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2023-24546");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("This advisory impacts the Arista CloudVision Portal products when run on-premise"));
        assertEquals("March 7, 2023", vuln.getPublishDate());
        assertEquals("March 7, 2023", vuln.getLastModifiedDate());
    }


    @Test
    public void testAristaMultiple() {
        String html = safeReadHtml("src/test/resources/test-arista-multiple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.arista.com/en/support/advisories-notices/security-advisory/15484-security-advisory-0077",
                html
        );
        assertEquals(2, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2021-28509");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("This advisory documents the impact of an internally found vulnerability in Arista EOS state streaming telemetry agent TerminAttr and OpenConfig transport protocols."));
        assertEquals("May 25th 2022", vuln.getPublishDate());
        assertEquals("May 27th 2022", vuln.getLastModifiedDate());
    }
}
