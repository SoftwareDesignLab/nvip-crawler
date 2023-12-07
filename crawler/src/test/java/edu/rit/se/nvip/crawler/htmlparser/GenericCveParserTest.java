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
import edu.rit.se.nvip.db.model.Vulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class GenericCveParserTest extends AbstractParserTest {
	static GenericCveParser parser;

	@BeforeAll
    public static void setupWebDriver(){
        parser = new GenericCveParser("nat_available", mock(SeleniumDriver.class));
    }
	
	@Test
	public void testJenkins() {
		String html = safeReadHtml("src/test/resources/test-jenkins.html");
		List<RawVulnerability> list = parser.parseWebPage("jenkins", html);
		RawVulnerability vuln = getVulnerability(list, "CVE-2017-1000355");
		assertNotNull(vuln);
	}

	@Test
	public void testAndroidCom() {

		String url = "https://source.android.com/security/bulletin/2017-09-01";
		String html = null;
		try {
			html = IOUtils.toString(new URL(url), StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
			fail();
		}
		List<RawVulnerability> list = parser.parseWebPage(url, html);
		assertTrue(list.size() > 1);
	}
	
	@Test
	public void testOpenwall() {
		String html = safeReadHtml("src/test/resources/test-openwall.html");
		List<RawVulnerability> list = parser.parseWebPage("openwall", html);
		RawVulnerability vuln = getVulnerability(list, "CVE-2015-4852");
		assertNotNull(vuln);
		boolean fine = vuln.getDescription().contains("Oracle");
		assertTrue(fine);
	}	

	@Test
	public void testChooseParserStrategy() {
		String tableHtml = safeReadHtml("src/test/resources/test-choose-table.html");
		ParserStrategy parserTable = parser.chooseParserStrategy(tableHtml);
		assertTrue(parserTable instanceof ParseTable);

		String listHtml = safeReadHtml("src/test/resources/test-generic_list_parser-naver.html");
		ParserStrategy parserList = parser.chooseParserStrategy(listHtml);
		assertTrue(parserList instanceof ParseList);

		String bulletinHtml = safeReadHtml("src/test/resources/test-android-bulletin.html");
		ParserStrategy parserBulletin = parser.chooseParserStrategy(bulletinHtml);
		assertTrue(parserBulletin instanceof ParseBulletin);

		String accordionHtml = safeReadHtml("src/test/resources/test-choose-accordion.html");
		ParserStrategy parserAccordion = parser.chooseParserStrategy(accordionHtml);
		assertTrue(parserAccordion instanceof ParseAccordion);
	}
}
