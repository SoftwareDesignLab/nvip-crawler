package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AristaParserTest extends AbstractParserTest {

    AristaParser parser = new AristaParser();

    @Test
    public void testAristaSingle() {
        String html = safeReadHtml("src/test/resources/test-arista-single.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.arista.com/en/support/advisories-notices/security-advisory/17022-security-advisory-0083",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-24546");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("This advisory impacts the Arista CloudVision Portal products when run on-premise"));
        assertEquals("2023-03-07 00:00:00", vuln.getPublishDate());
        assertEquals("2023-03-07 00:00:00", vuln.getLastModifiedDate());
    }


    @Test
    public void testAristaMultiple() {
        String html = safeReadHtml("src/test/resources/test-arista-multiple.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.arista.com/en/support/advisories-notices/security-advisory/15484-security-advisory-0077",
                html
        );
        assertEquals(2, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2021-28509");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("This advisory documents the impact of an internally found vulnerability in Arista EOS state streaming telemetry agent TerminAttr and OpenConfig transport protocols."));
        assertEquals("2022-05-25 00:00:00", vuln.getPublishDate());
        assertEquals("2022-05-27 00:00:00", vuln.getLastModifiedDate());
    }
}
