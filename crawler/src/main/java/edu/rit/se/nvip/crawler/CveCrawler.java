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
package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.crawler.htmlparser.AbstractCveParser;
import edu.rit.se.nvip.crawler.htmlparser.CveParserFactory;

import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.crawler.WebCrawler;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.url.WebURL;
import edu.rit.se.nvip.db.model.RawVulnerability;

import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;

/**
 *
 * NVIP CVE Crawler
 *
 * @author axoeec
 *
 */
@Slf4j
public class CveCrawler extends WebCrawler {

	private final static Pattern FILTERS = Pattern.compile(".*(\\.(css|js|gif|jpg" + "|png|mp3|mp4|zip|gz))$");
	private final List<String> myCrawlDomains;
	private String outputDir;
	private final HashMap<String, ArrayList<RawVulnerability>> foundCVEs = new HashMap<>();
	private final CveParserFactory parserFactory = new CveParserFactory();

	private SeleniumDriver driver;


	public CveCrawler(List<String> myCrawlDomains, String outputDir) {
		this.myCrawlDomains = myCrawlDomains;
		this.outputDir = outputDir;
		this.driver = new SeleniumDriver();
	}

	public SeleniumDriver getSeleniumDriver(){
		return driver;
	}

	@Override
	public void onBeforeExit() {
        driver.tryDiverQuit();
    }

	/**
	 * get Cve data from crawler thread
	 */
	@Override
	public HashMap<String, ArrayList<RawVulnerability>> getMyLocalData() {
		return foundCVEs;
	}

	/**
	 * This method receives two parameters. The first parameter is the page in which
	 * we have discovered this new url and the second parameter is the new url. You
	 * should implement this function to specify whether the given url should be
	 * crawled or not (based on your crawling logic).
	 */
	@Override
	public boolean shouldVisit(Page referringPage, WebURL url) {
		String href = url.getURL().toLowerCase(Locale.ROOT);
		if (FILTERS.matcher(href).matches()) {
			return false;
		}

		for (String crawlDomain : myCrawlDomains) {
			if (href.startsWith(crawlDomain)) {
				return true;
			}
		}

		return false;
	}

	private String getPageHtml(Page page, String url) {
		//TODO: move this list
		List<String> dynamicSeeds = Arrays.asList("redhat", "tibco", "autodesk", "trustwave", "mend.io");
		if (dynamicSeeds.stream().anyMatch(url::contains)) {
			log.info("Getting content from page with dynamically-loaded HTML {}", url);
			return QuickCveCrawler.getContentFromDynamicPage(url, driver.getDriver());
		}
		HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
		return htmlParseData.getHtml();
	}

	/**
	 * Page is ready to be processed.
	 */
	@Override
	public void visit(Page page) {
		String pageURL = page.getWebURL().getURL();

		if (!shouldVisit(page, page.getWebURL())) {
			log.info("Skipping URL: {}", pageURL);
		} else if (page.getParseData() instanceof HtmlParseData) {
//			log.info("Parsing {}", pageURL);
			HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
			String html = htmlParseData.getHtml();

			// get vulnerabilities from page
			List<RawVulnerability> vulnerabilityList = new ArrayList<>();
			try {
				vulnerabilityList = parseWebPage(pageURL, html);
			} catch (Exception e) {
				log.warn("WARNING: Crawler error when parsing {} --> {}", page.getWebURL(), e.toString());
				log.error("", e);
				updateCrawlerReport("Crawler error when parsing " +  page.getWebURL() +" --> " + e);
			}

			if (vulnerabilityList.isEmpty()) {
				log.warn("WARNING: No CVEs found at {}!", pageURL);
				updateCrawlerReport("No CVEs found at " + pageURL + "!");
			} else {
				for (RawVulnerability vulnerability : vulnerabilityList) {
					if (vulnerability.getCveId().isEmpty()) {
						log.info("A cve found by the {} parser at the URL {} has an empty cve_id and will not be inserted", vulnerability.getParserType(), vulnerability.getSourceUrl());
						continue;
					}
					if (foundCVEs.get(vulnerability.getCveId()) != null) {
						foundCVEs.get(vulnerability.getCveId()).add(vulnerability);
					} else {
						ArrayList<RawVulnerability> newList = new ArrayList<>();
						newList.add(vulnerability);
						foundCVEs.put(vulnerability.getCveId(), newList);
					}
				}
				log.info("{} CVEs found at {}", vulnerabilityList.size(),pageURL);
			}
		}
	}

	/**
	 * parse this page with an appropriate parser and return vulnerabilities found
	 *
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		// get parser and parse
		AbstractCveParser parser = parserFactory.createParser(sSourceURL, driver);
		return parser.parseWebPage(sSourceURL, sCVEContentHTML);
	}

	private void updateCrawlerReport(String crawlerLog) {
		File reportFile = new File(outputDir);
		try {
			reportFile.createNewFile();
			FileWriter write = new FileWriter(reportFile, true);
			write.write(crawlerLog + "\n");
			write.close();
		} catch (IOException e) {
			log.info("Failure writing report to {}: {}", outputDir, e);
		}
	}
}
