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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test RedHat Parser
 */
@ExtendWith(MockitoExtension.class)
public class RedHatParserTest extends AbstractParserTest {

	@Mock SeleniumDriver driver;

	@InjectMocks RedHatParser parser = new RedHatParser();

	@Test
	public void testRedHat() {
		String html = safeReadHtml("src/test/resources/test-redhat-security-3.html");

		when(driver.tryPageGet("https://access.redhat.com/security/cve/cve-2023-25725"))
				.thenReturn(html);

		html = parser.grabDynamicHTML("https://access.redhat.com/security/cve/cve-2023-25725", driver);

		List<RawVulnerability> list = parser.parseWebPage("https://access.redhat.com/security/cve/cve-2023-25725", html);

		assertEquals(1, list.size());

		RawVulnerability sample = list.get(0);
		assertEquals("CVE-2023-25725", sample.getCveId());
		assertTrue(sample.getDescription().contains("A flaw was found in HAProxy's headers processing that causes HAProxy to drop important headers fields such as Connection, Content-length, Transfer-Encoding,"));
		assertEquals("2023-02-14 16:20:00", sample.getPublishDateString());
		// assertEquals("2023-06-24 10:06:14", sample.getLastModifiedDateString());

	}
}
