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
package edu.rit.se.nvip;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Ignore;
import org.junit.Test;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import org.junit.jupiter.api.BeforeEach;

public class NVIPMainTest {

	private NVIPMain main = new NVIPMain();

	private final String CVEID1 = "CVE-2020-0227";
	private final String CVEID2 = "CVE-2020-0228";


	@BeforeEach
	public void setup() {
		main = new NVIPMain();
	}

	@Test
	public void testEssentialData() {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		/**
		 * Test the existence of VDO training data for characterization
		 */

		String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
		int kbyte = 1024;
		int mbyte = kbyte * 1024;

		String vdoTrainingFile = trainingDataInfo[0] + trainingDataInfo[1].split(",")[0];
		File f3 = new File(vdoTrainingFile);

		int f3Length = (int) f3.length() / kbyte;

		assertEquals(true, f3.exists() && (f3Length > 10));
	}

	/**
	 * Test CVE Crawl Function

	@Test
	public void testCrawlCVE() {
		NVIPMain main = new NVIPMain(false);

		List<String> urls = main.startNvip();
		HashMap<String, CompositeVulnerability> vulns = main.crawlCVEs(urls);

		System.out.println(vulns);
	}*/

	/**
	 * Test description comparing via Git and CNA descriptions
	 */
	@Test
	public void testDescriptionCompare() {
		String testDescriptionCNA = "Test CVE Description, this should not be changed";
		String testDescriptionReserved = "** RESERVED ** This candidate has been reserved";
		String expectedResult = "** RESERVED ** - NVIP Description: Test CVE Description, this should not be changed";

		HashMap<String, CompositeVulnerability > cvehashMapGithub = new HashMap<>();
		cvehashMapGithub.put("CVE-2022-30080", new CompositeVulnerability(0, "sourcURL",
				"CVE-2022-30080", null, "2022-05-02", "2022-05-02",
				testDescriptionReserved, "domain"));

		HashMap<String, CompositeVulnerability > cveHashMapScrapedFromCNAs = new HashMap<>();
		cveHashMapScrapedFromCNAs.put("CVE-2022-30080", new CompositeVulnerability(0, "sourcURL",
				"CVE-2022-30080", null, "2022-05-02", "2022-05-02",
				testDescriptionCNA, "domain"));

		//HashMap<String, CompositeVulnerability> merge = new NVIPMain(false).
		//		mergeCVEsDerivedFromCNAsAndGit(cvehashMapGithub, cveHashMapScrapedFromCNAs);

		//assertEquals(expectedResult, merge.get("CVE-2022-30080").getDescription());

	}

	@Test
	public void testMergeCrawlResults() {

		// Prepare test list for non scraped raw data
		List<CompositeVulnerability> nonScrapedRawData = new ArrayList<>();
		CompositeVulnerability rawVuln1 = new CompositeVulnerability(0, CVEID1);
		rawVuln1.setDescription("Test Description for raw vuln 1");
		nonScrapedRawData.add(rawVuln1);

		// Prepare test list for scraped raw data
		ArrayList<CompositeVulnerability> scrapedRawData = new ArrayList<>();
		CompositeVulnerability rawVuln2 = new CompositeVulnerability(0, CVEID2);
		rawVuln2.setDescription("Test Description for raw vuln 2");
		scrapedRawData.add(rawVuln2);

		// Fill hashmaps and test merge
		HashMap<String, List<CompositeVulnerability>> cvesNotScraped = new HashMap<>();
		HashMap<String, ArrayList<CompositeVulnerability>> cvesScrapedFromCNAs = new HashMap<>();
		cvesNotScraped.put(CVEID1, nonScrapedRawData);
		cvesScrapedFromCNAs.put(CVEID2, scrapedRawData);

		HashMap<String, CompositeVulnerability> mergedData = main.mergeCVEsDerivedFromCNAsAndGit(cvesNotScraped, cvesScrapedFromCNAs);

		assertEquals(2, mergedData.size());
		assertEquals(CVEID1, mergedData.get(CVEID1).getCveId());
		assertEquals(CVEID2, mergedData.get(CVEID2).getCveId());
		assertEquals("Test Description for raw vuln 1", mergedData.get(CVEID1).getDescription());
		assertEquals("Test Description for raw vuln 2", mergedData.get(CVEID2).getDescription());
	}

	@Test
	public void testMergeCVEsMultipleSources() {

		// Prepare test list for non scraped raw data
		List<CompositeVulnerability> nonScrapedRawData = new ArrayList<>();
		CompositeVulnerability rawVuln1 = new CompositeVulnerability(0, CVEID1);
		rawVuln1.addSourceURL("test source 1");
		rawVuln1.setDescription("Test Description for raw vuln 1");
		nonScrapedRawData.add(rawVuln1);

		// Prepare test list for scraped raw data
		ArrayList<CompositeVulnerability> scrapedRawData = new ArrayList<>();
		CompositeVulnerability rawVuln2 = new CompositeVulnerability(0, CVEID1);
		rawVuln2.addSourceURL("test source 1");
		rawVuln2.addSourceURL("test source 2");
		rawVuln2.setDescription("Test Description for raw vuln 1");
		scrapedRawData.add(rawVuln2);

		// Fill hashmaps and test merge
		HashMap<String, List<CompositeVulnerability>> cvesNotScraped = new HashMap<>();
		HashMap<String, ArrayList<CompositeVulnerability>> cvesScrapedFromCNAs = new HashMap<>();
		cvesNotScraped.put(CVEID1, nonScrapedRawData);
		cvesScrapedFromCNAs.put(CVEID1, scrapedRawData);

		HashMap<String, CompositeVulnerability> mergedData = main.mergeCVEsDerivedFromCNAsAndGit(cvesNotScraped, cvesScrapedFromCNAs);

		assertEquals(1, mergedData.size());
		assertEquals(CVEID1, mergedData.get(CVEID1).getCveId());
		assertEquals("Test Description for raw vuln 1\n\n\nTest Description for raw vuln 1", mergedData.get(CVEID1).getDescription());
		assertEquals(2, mergedData.get(CVEID1).getSourceURL().size());
		assertEquals("test source 1", mergedData.get(CVEID1).getSourceURL().get(0));

	}
}
