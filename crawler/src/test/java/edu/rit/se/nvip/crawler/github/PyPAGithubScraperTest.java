/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

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