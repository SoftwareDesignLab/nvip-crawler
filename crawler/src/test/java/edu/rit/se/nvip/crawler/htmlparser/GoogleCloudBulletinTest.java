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


/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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
import edu.rit.se.nvip.db.model.RawVulnerability;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

/**
 * Test for Google Cloud Bulletin Parser
 */
public class GoogleCloudBulletinTest extends AbstractParserTest {

    GoogleCloudParser parser = new GoogleCloudParser();

    @Test
    public void testGoogleCloudsecurityBulletinParser() throws IOException {

        String html = FileUtils.readFileToString(new File("src/test/resources/test-google-cloud-bulletin.html"), StandardCharsets.US_ASCII);
        List<RawVulnerability> list = parser.parseWebPage("https://cloud.google.com/support/bulletins", html);

        assertEquals(52, list.size());

        RawVulnerability vuln1 = list.get(0);
        RawVulnerability vuln6 = list.get(5);

        assertEquals("CVE-2022-3786", vuln1.getCveId());
        assertEquals("2023-01-11 00:00:00", vuln1.getPublishDateString());
        assertEquals("2023-01-11 00:00:00", vuln1.getLastModifiedDateString());
        assertTrue(vuln1.getDescription().contains("OpenSSL v3.0.6 that can potentially cause a crash."));
        assertEquals("CVE-2022-2588", vuln6.getCveId());
        assertEquals("2022-11-09 00:00:00", vuln6.getPublishDateString());
        assertEquals("2023-01-19 00:00:00", vuln6.getLastModifiedDateString());
        assertTrue(vuln6.getDescription().contains("Linux kernel that can lead to a full container break out to root on the node."));

    }

    // We should not parse non-english Google Cloud bulletins
    @Test
    public void testGoogleCloudParserJapBulletin() {
        QuickCveCrawler q = new QuickCveCrawler();
        String html = q.getContentFromUrl("https://cloud.google.com/support/bulletins?hl=ja");
        List<RawVulnerability> list = new GoogleCloudParser("google").parseWebPage("cloud.google", html);
        assertEquals(0, list.size());
    }

}
