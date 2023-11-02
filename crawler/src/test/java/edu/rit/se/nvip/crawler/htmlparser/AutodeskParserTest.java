/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
public class AutodeskParserTest extends AbstractParserTest{

    @Mock static SeleniumDriver driver;

    AutodeskParser parser = new AutodeskParser();

    @Test
    public void testAutodesk() {
        String html = safeReadHtml("src/test/resources/test-autodesk-table-multi.html");
        List<RawVulnerability> list = parser.parseWebPage("autodesk", html);
        assertEquals(18, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2021-45960");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Expat"));
        assertTrue(vuln.getDescription().contains("Autodesk products leveraging internal components"));
        assertEquals("2022-07-28 00:00:00", vuln.getLastModifiedDate());
        assertEquals("2022-10-12 00:00:00", vuln.getPublishDate());

        vuln = getVulnerability(list, "CVE-2021-22947");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Curl"));
    }

    @Test
    public void testAutodeskMulti() {
        String html = safeReadHtml("src/test/resources/test-autodesk-multi-desc.html");
        List<RawVulnerability> list = parser.parseWebPage("autodesk", html);
        assertEquals(4, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-33890");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("A maliciously crafted PCT"));
        assertFalse(vuln.getDescription().contains("Applications and services that utilize"));
        assertEquals("2022-12-14 00:00:00", vuln.getPublishDate());
        assertEquals("2022-12-14 00:00:00", vuln.getLastModifiedDate());
    }
}
