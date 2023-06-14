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
package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.crawler.htmlparser.AbstractCveParser;
import edu.rit.se.nvip.crawler.htmlparser.CveParserFactory;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.crawler.WebCrawler;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.url.WebURL;
import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

/**
 *
 * NVIP CVE Crawler
 *
 * @author axoeec
 *
 */
public class CveCrawler extends WebCrawler {

	private final Logger nvip_logger = LogManager.getLogger(getClass().getSimpleName());
	private final static Pattern FILTERS = Pattern.compile(".*(\\.(css|js|gif|jpg" + "|png|mp3|mp4|zip|gz))$");
	private final List<String> myCrawlDomains;
	private String outputDir;
	private final HashMap<String, ArrayList<RawVulnerability>> foundCVEs = new HashMap<>();
	private final CveParserFactory parserFactory = new CveParserFactory();

	private WebDriver driver;


	public CveCrawler(List<String> myCrawlDomains, String outputDir) {
		this.myCrawlDomains = myCrawlDomains;
		this.outputDir = outputDir;
		this.driver = startDynamicWebDriver();
	}

	public static WebDriver startDynamicWebDriver() {
		System.setProperty("webdriver.chrome.silentOutput", "true");
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless=new","--user-agent=Mozilla/5.0");
		options.addArguments("--remote-allow-origins=*");
		options.addArguments("--enable-javascript");
		options.addArguments("--no-sandbox");
		options.addArguments("--disable-dev-shm-usage");
		Map<String, Object> timeouts = new HashMap<>();
		timeouts.put("implicit", 20);
		timeouts.put("pageLoad", 15000);
		timeouts.put("script", 60000);
		options.setCapability("timeouts", timeouts);
		WebDriverManager.chromedriver().setup();
		ChromeDriverService chromeDriverService = new ChromeDriverService.Builder().build();
		return new ChromeDriver(chromeDriverService, options);
	}

	/**
	 * get Cve data from crawler thread
	 */
	@Override
	public HashMap<String, ArrayList<RawVulnerability>> getMyLocalData() {
		this.driver.quit();
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
			logger.info("Getting content from page with dynamically-loaded HTML {}", url);
			return QuickCveCrawler.getContentFromDynamicPage(url, driver);
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
			logger.info("Skipping URL: {}", pageURL);
		} else if (page.getParseData() instanceof HtmlParseData) {
//			logger.info("Parsing {}", pageURL);
			HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
			String html = htmlParseData.getHtml();

			// get vulnerabilities from page
			List<RawVulnerability> vulnerabilityList = new ArrayList<>();
			try {
				vulnerabilityList = parseWebPage(pageURL, html);
			} catch (Exception e) {
				logger.warn("WARNING: Crawler error when parsing {} --> {}", page.getWebURL(), e.toString());
				e.printStackTrace();
				updateCrawlerReport("Crawler error when parsing " +  page.getWebURL() +" --> " + e);
			}

			if (vulnerabilityList.isEmpty()) {
				nvip_logger.warn("WARNING: No CVEs found at {}!", pageURL);
				updateCrawlerReport("No CVEs found at " + pageURL + "!");
			} else {
				for (RawVulnerability vulnerability : vulnerabilityList) {
					if (foundCVEs.get(vulnerability.getCveId()) != null) {
						foundCVEs.get(vulnerability.getCveId()).add(vulnerability);
					} else {
						ArrayList<RawVulnerability> newList = new ArrayList<>();
						newList.add(vulnerability);
						foundCVEs.put(vulnerability.getCveId(), newList);
					}
				}
				nvip_logger.info("{} CVEs found at {}", vulnerabilityList.size(),pageURL);
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

	private void updateCrawlerReport(String log) {
		File reportFile = new File(outputDir);
		try {
			reportFile.createNewFile();
			FileWriter write = new FileWriter(reportFile, true);
			write.write(log + "\n");
			write.close();
		} catch (IOException e) {
			logger.info("Failure writing report to {}: {}", outputDir, e);
		}
	}

}
