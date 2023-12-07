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

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.db.model.RawVulnerability;
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import static org.junit.Assert.assertEquals;

/**
 * Test Parser for VMWare Security Advisories Page
 * @author aep7128
 *
 * There is an older version of this page for earlier CVEs,
 * but CVE Descriptions aren't accuratly shown (ex. 4 CVEs have the same description,
 * then redirects to MITRE), we may want to ignore those cases for now. Just test on the recent web page layout
 *
 */
public class VMWareAdvisoriesTest extends AbstractParserTest {

	VMWareAdvisoriesParser parser = new VMWareAdvisoriesParser();

	/**
	 * Test Parser for page that has 1 CVE
	 * @throws IOException
	 */
	@Test
	public void testVMWareAdvisoriesSingleCVE() throws IOException {
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories-single-cve.html"), StandardCharsets.UTF_8);
		List<RawVulnerability> list = parser.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0003.html", html);

		assertEquals(list.size(), 1);

		RawVulnerability vuln = list.get(0);

		assertEquals(vuln.getCveId(), "CVE-2023-20854");
		assertEquals(vuln.getDescription(), "VMware Workstation contains an arbitrary file deletion vulnerability. VMware has evaluated the severity of this issue to be in the Important severity range with a maximum CVSSv3 base score of 7.8.");
		assertEquals(vuln.getPublishDateString(), "2023-02-02 00:00:00");
		assertEquals(vuln.getLastModifiedDateString(), "2023-02-02 00:00:00");

	}

	/**
	 * Test Parser for page with multiple CVEs
	 * @throws IOException
	 */
	@Test
	public void testVMWareAdvisoriesMultiCVE() throws IOException {
		String html = FileUtils.readFileToString(new File("src/test/resources/test-vmware-advisories-multi-cve.html"), StandardCharsets.UTF_8);
		List<RawVulnerability> list = parser.parseWebPage("https://www.vmware.com/security/advisories/VMSA-2023-0001.html", html);

		assertEquals(list.size(), 4);

		RawVulnerability vuln = list.get(0);

		assertEquals("CVE-2022-31706", vuln.getCveId());
		assertEquals("The vRealize Log Insight contains a Directory Traversal Vulnerability. VMware has evaluated the severity of this issue to be in the critical severity range with a maximum CVSSv3 base score of 9.8.", vuln.getDescription());
		assertEquals("2023-01-24 00:00:00", vuln.getPublishDateString());
		assertEquals("2023-01-31 00:00:00", vuln.getLastModifiedDateString());

	}

}
