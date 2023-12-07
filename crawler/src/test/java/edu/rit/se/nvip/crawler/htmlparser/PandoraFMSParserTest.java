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

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class PandoraFMSParserTest extends AbstractParserTest {

    PandoraFMSRootParser parser = new PandoraFMSRootParser();

    @Test
    public void testPandoraFMSParser() {
        String html = safeReadHtml("src/test/resources/test-pandorafms.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/",
                html
        );
        assertEquals(65, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-24517");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Remote Code Execution via Unrestricted File Upload"));
        assertEquals("2023-02-21 00:00:00", vuln.getPublishDateString());
    }
}
