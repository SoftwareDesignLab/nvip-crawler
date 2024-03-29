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

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;

public class SnykParserTest extends AbstractParserTest {

    SnykParser parser = new SnykParser();

    @Test
    public void testSnykCve() {
        String html = safeReadHtml("src/test/resources/test-snyk.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://security.snyk.io/vuln/SNYK-RUST-CRANELIFTCODEGEN-3357941",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-26489", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("translates code from an intermediate representation"));
        assertEquals("2023-03-09 00:00:00", vuln.getPublishDateString());
    }

    @Test
    public void testSnykNoCve() {
        String html = safeReadHtml("src/test/resources/test-snyk-no.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://security.snyk.io/vuln/SNYK-PYTHON-BINGCHILLING2-3358386",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testSnykCveDetailed() {
        String html = safeReadHtml("src/test/resources/test-snyk-details.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://security.snyk.io/vuln/SNYK-PHP-MOODLEMOODLE-3356645",
                html
        );
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2021-36401", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("Escaping means that the application is coded to mark key char"));
        assertEquals("2023-03-08 00:00:00", vuln.getPublishDateString());
    }
}
