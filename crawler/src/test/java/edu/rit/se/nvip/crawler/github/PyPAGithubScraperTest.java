package edu.rit.se.nvip.crawler.github;

import edu.rit.se.nvip.db.model.RawVulnerability;

import org.junit.Test;

import java.util.HashMap;

import static org.junit.Assert.*;

/**
 * Tests for PyPA scraper/parser
 */
//TODO: Don't run this test
public class PyPAGithubScraperTest {

    @Test
    public void testPyPA() {
        PyPAGithubScraper scraper = new PyPAGithubScraper();
        HashMap<String, RawVulnerability> out = scraper.scrapePyPAGithub();
        RawVulnerability vuln = out.get("CVE-2017-16763");

        assertEquals(vuln.getCveId(), "CVE-2017-16763");
        assertTrue(vuln.getDescription().contains("An exploitable vulnerability exists in the YAML parsing functionality in config.py in Confire 0.2.0"));
        assertEquals("2017-11-10 09:29:00", vuln.getPublishDateString());
        assertEquals("2021-08-25 04:29:57", vuln.getLastModifiedDateString());
    }
}