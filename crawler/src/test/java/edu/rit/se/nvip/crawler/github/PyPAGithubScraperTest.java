package edu.rit.se.nvip.crawler.github;

import edu.rit.se.nvip.model.RawVulnerability;

import org.junit.Test;

import java.util.HashMap;

import static org.junit.Assert.*;

/**
 * Tests for PyPA scraper/parser
 */
public class PyPAGithubScraperTest {
    @Test
    public void testPyPA() {
        PyPAGithubScraper scraper = new PyPAGithubScraper();
        HashMap<String, RawVulnerability> out = scraper.scrapePyPAGithub();
        RawVulnerability vuln = out.get("CVE-2017-16763");

        assertEquals(vuln.getCveId(), "CVE-2017-16763");
        assertTrue(vuln.getDescription().contains("An exploitable vulnerability exists in the YAML parsing functionality in config.py in Confire 0.2.0"));
        assertEquals(vuln.getPublishDate(), "2017-11-10 09:29:00");
        assertEquals(vuln.getLastModifiedDate(), "2021-08-25 04:29:57");
    }
}