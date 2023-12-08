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
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseBulletinTest extends AbstractParserTest {

    // test against Android Bulletin
    @Test
    public void testParseBulletinAndroid() {
        ParseBulletin parser = new ParseBulletin("https://source.android.com/docs/security/bulletin/2023-02-01");
        String html = safeReadHtml("src/test/resources/test-android-bulletin.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://source.android.com/docs/security/bulletin/2023-02-01",
                html
        );
        assertEquals(40, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-20933");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("with no additional execution privileges needed"));
        assertEquals("2023-02-06 00:00:00", vuln.getPublishDateString());
        assertEquals("2023-02-08 00:00:00", vuln.getLastModifiedDateString());
    }


    // test against Google Cloud Bulletin
    @Test
    public void testParseBulletinGoogle() throws IOException {
        String html = FileUtils.readFileToString(new File("src/test/resources/test-google-cloud-bulletin.html"), StandardCharsets.US_ASCII);
        ParseBulletin parser = new ParseBulletin("https://cloud.google.com/support/bulletins/");
        List<RawVulnerability> list = parser.parseWebPage("https://cloud.google.com/support/bulletins", html);
        assertTrue(list.size() > 90);
        RawVulnerability vuln1 = getVulnerability(list, "CVE-2022-3786");
        RawVulnerability vuln6 = getVulnerability(list, "CVE-2022-2588");
        assertNotNull(vuln1);
        assertNotNull(vuln6);
        assertEquals("2023-01-11 00:00:00", vuln1.getPublishDateString());
        assertEquals("2023-01-11 00:00:00", vuln1.getLastModifiedDateString());
        assertTrue(vuln1.getDescription().contains("OpenSSL v3.0.6 that can potentially cause a crash."));
        assertEquals("2022-11-09 00:00:00", vuln6.getPublishDateString());
        assertEquals("2023-01-19 00:00:00", vuln6.getLastModifiedDateString());
        assertTrue(vuln6.getDescription().contains("Linux kernel that can lead to a full container break out to root on the node."));
    }
}
