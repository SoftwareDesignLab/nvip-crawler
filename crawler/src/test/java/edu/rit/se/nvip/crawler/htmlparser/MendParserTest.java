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

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.model.RawVulnerability;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import java.util.List;
import static junit.framework.TestCase.*;

/**
 * Test MendParser, verify proper CVE extraction
 */
public class MendParserTest extends AbstractParserTest{

    @Test
    public void testMend() {
        CveCrawler crawler = getCrawler();
        String html = safeReadHtml("src/test/resources/test-mend.html");
        List<RawVulnerability> list = crawler.parseWebPage(
                "https://www.mend.io/vulnerability-database/CVE-2023-22736",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-22736", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("Making sure all AppProjects' sourceNamespaces are"));
        assertEquals("2023-01-26 00:00:00", vuln.getPublishDate());
    }

    @Test
    public void testMend2() {
        MendParser parser = new MendParser("mend");
        String html = parser.grabDynamicHTML("https://www.mend.io/vulnerability-database/CVE-2013-6646");
        List<RawVulnerability> list = new MendParser("mend").parseWebPage(
                "https://www.mend.io/vulnerability-database/CVE-2013-6646",
                html
        );
        assertEquals(1, list.size());
    }

    @BeforeClass
    public static void setupWebDriver(){
        if(CveCrawler.driver.toString().contains("(null)")) CveCrawler.driver = CveCrawler.startDynamicWebDriver();
    }

    @AfterClass
    public static void destroyWebDriver(){
        if(CveCrawler.driver != null) CveCrawler.driver.quit();
    }
}
