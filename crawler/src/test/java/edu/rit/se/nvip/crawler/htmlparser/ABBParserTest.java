/**
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
*/

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class ABBParserTest extends AbstractParserTest {

    ABBParser parser = new ABBParser();

    @Test
    public void testABBDownloadAndParse() {
        String html = safeReadHtml("src/test/resources/test-abb.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://search.abb.com/library/Download.aspx?DocumentID=7PAA007893&LanguageCode=en&DocumentPartId=&Action=Launch",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-0580", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("An attacker who successfully exploited this vulnerability could gain access to the protected application"));
        assertEquals("2023-03-27 00:00:00", vuln.getPublishDateString());
        assertEquals("2023-03-27 00:00:00", vuln.getLastModifiedDateString());
    }
}
