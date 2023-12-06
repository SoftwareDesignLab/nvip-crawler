/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import edu.rit.se.nvip.crawler.SeleniumDriver;
import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
public class GitHubAdvisoryParserTest extends AbstractParserTest {

    @Mock SeleniumDriver driver;

    @InjectMocks
    static GitHubAdvisoryParser parser;

    /**
     * Test page with 1 CVE and contains an Impact description section
     */
    @Test
    public void testGitHubAdvisories1() {
        String html = safeReadHtml("src/test/resources/test-github-1.html");
        when(driver.tryPageGet("https://github.com/advisories/GHSA-xm67-587q-r2vw"))
                .thenReturn(html);

        List<RawVulnerability> list = parser.parseWebPage(
                "https://github.com/advisories/GHSA-xm67-587q-r2vw",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-27477", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("There is an off-by-one error in the calculation of the mask to the"));
        assertFalse(vuln.getDescription().contains("If you have any questions or comments about this advisory"));
        assertEquals("2023-03-08 19:38:37", vuln.getPublishDateString());
        assertEquals("2023-03-09 00:09:04", vuln.getLastModifiedDateString());
    }

    /**
     * Test page with a CVE, no impact section, and mentioned 'last week' as date
     */
    @Test
    public void testGitHubAdvisories2() {
        String html = safeReadHtml("src/test/resources/test-github-2.html");
        when(driver.tryPageGet("https://github.com/advisories/GHSA-wxfj-84xf-7gxv"))
                .thenReturn(html);

        List<RawVulnerability> list = parser.parseWebPage(
                "https://github.com/advisories/GHSA-wxfj-84xf-7gxv",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-26105", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("All versions of the package utilities are vulnerable to Prototype Pollution via the _mix function."));
        assertEquals("2023-02-28 06:30:25", vuln.getPublishDateString());
        assertEquals("2023-03-08 23:14:00", vuln.getLastModifiedDateString());
    }

    /**
     * Test page with no known CVE listed for it
     */
    @Test
    public void testGitHubAdvisories3() {
        String html = safeReadHtml("src/test/resources/test-github-3.html");
        when(driver.tryPageGet("https://github.com/advisories/GHSA-mrrw-grhq-86gf"))
                .thenReturn(null);
        List<RawVulnerability> list = parser.parseWebPage(
                "https://github.com/advisories/GHSA-mrrw-grhq-86gf",
                html
        );
        assertEquals(0, list.size());
    }
}
