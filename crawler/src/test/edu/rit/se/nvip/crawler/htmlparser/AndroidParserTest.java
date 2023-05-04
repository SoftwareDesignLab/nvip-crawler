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

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AndroidParserTest extends AbstractParserTest {

    @Test
    public void testAndroidBulletin() {
        String html = safeReadHtml("src/test/resources/test-android-bulletin.html");
        List<RawVulnerability> list = crawler.parseWebPage(
                "https://source.android.com/docs/security/bulletin/2023-02-01",
                html
        );
        assertEquals(40, list.size());
        RawVulnerability vuln = list.get(8);
        assertEquals("CVE-2023-20933", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("local escalation of privilege with no additional execution privileges needed"));
        assertFalse(vuln.getDescription().contains("lead to remote code execution with no additional"));
        assertEquals("2023-02-06 00:00:00", vuln.getPublishDate());
        assertEquals("2023-02-08 00:00:00", vuln.getLastModifiedDate());
    }

}
