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
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AdobeParserTest extends AbstractParserTest {

    AdobeParser parser = new AdobeParser();

    @Test
    public void testAdobe() {
        String html = safeReadHtml("src/test/resources/test-adobe.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://helpx.adobe.com/security/products/magento/apsb23-17.html",
                html
        );
        assertEquals(4, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-22247");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Adobe has released a security update for Adobe Commerce and Magento Open Source."));
        assertEquals("2023-03-14 00:00:00", vuln.getPublishDate());
        assertEquals("2023-03-14 00:00:00", vuln.getLastModifiedDate());

    }
}
