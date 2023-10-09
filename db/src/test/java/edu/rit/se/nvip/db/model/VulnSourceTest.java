package edu.rit.se.nvip.db.model;

import edu.rit.se.nvip.db.model.VulnSource;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for VulnSource Model
 */
public class VulnSourceTest {
    @Test
    public void testVulnSource() {
        VulnSource obj = new VulnSource("cve_id", "url");

        assertEquals(obj.getCveId(), "cve_id");
        assertEquals(obj.getUrl(), "url");

        obj.setCveId("new_cve_id");
        obj.setUrl("new_url");

        assertEquals(obj.getCveId(), "new_cve_id");
        assertEquals(obj.getUrl(), "new_url");
    }

    @Test
    public void testEquals() {
        String url = "https://talosintelligence.com/vulnerability_reports/TALOS-2016-0036";
        VulnSource vuln = new VulnSource("", url);
        VulnSource vuln2 = new VulnSource("", url);

        boolean ok = vuln.equals(vuln2);
        assertTrue(ok);

        vuln = new VulnSource("", url);
        vuln2 = new VulnSource("", url + "X");
        ok = vuln.equals(vuln2);
        assertFalse(ok);

        vuln2 = null;
        ok = vuln.equals(vuln2);
        assertFalse(ok);

        ok = vuln.equals("test");
        assertFalse(ok);
    }
}