/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import io.github.bonigarcia.wdm.WebDriverManager;
import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.NullOutputStream;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import edu.rit.se.nvip.utils.UtilHelper;

import javax.net.ssl.SSLException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.temporal.IsoFields;
import java.util.*;

/**
 * This class scrapes most recent CVEs from a list of known sources quickly:
 * 
 * Examples: https://www.tenable.com/cve/newest
 * https://packetstormsecurity.com/files/date/yyyy-MM-dd/
 * 
 * @author axoeec
 *
 */
@Slf4j
public class QuickCveCrawler {
	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36";

	public List<RawVulnerability> getCVEsfromKnownSummaryPages() {

		List<RawVulnerability> list = new ArrayList<>();
		CveCrawler crawler = new CveCrawler(new ArrayList<>(), "");

		// Seclists
		getSeclistsCveUpdates(crawler, list);

		// Cnnvd
		// getCnnvdCveUpdates(list);

		// packet storm
		getPacketStrormCveUpdates(crawler, list);

		// Tenable
		getTenableCveUpdates(crawler, list);

		crawler.getSeleniumDriver().tryDiverQuit();

		return list;
	}

	/**
	 * Scrape Packetstorm
	 * 
	 * @param crawler
	 * @param list
	 * @return
	 */
	public List<RawVulnerability> getPacketStrormCveUpdates(CveCrawler crawler, List<RawVulnerability> list) {
		try {
			String url = "https://packetstormsecurity.com/files/date/";
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");
			Calendar cal = Calendar.getInstance();
			int count = list.size();

			for (int day = 1; day < 7; day++) {
				cal.add(Calendar.DATE, -1 * day);
				String date = dateFormat.format(cal.getTime());
				String link = url + date;
				log.info("Scraping most recent CVEs from {}", link);
				try {
					String html = getContentFromUrl(link);
					list.addAll(crawler.parseWebPage(link, html));
					Thread.sleep(1000);
				} catch (Exception e) {
					log.error("Error scraping url {}, {}", link, e.toString());
				}
			}

			log.info("Retrieved {} CVES from {}, Total CVEs: {}", list.size() - count, url, list.size());
		} catch (Exception e) {
			log.error("Error scraping PacketStorm! {}", e);
		}
		return list;
	}

	/**
	 * Scrape Tenable
	 * 
	 * @param crawler
	 * @param list
	 * @return
	 */
	public List<RawVulnerability> getTenableCveUpdates(CveCrawler crawler, List<RawVulnerability> list) {
		String url = "https://www.tenable.com/cve/newest";

		try {
			int count = list.size();
			log.info("Getting CVES from {} ", url);
			String html = getContentFromUrl(url);
			list.addAll(crawler.parseWebPage(url, html));
			log.info("Retrieved {} CVES from {}, Total CVEs: {}", list.size() - count, url, list.size());
		} catch (Exception e) {
			log.error("Error scraping url {}, {}", url, e.toString());
		}
		return list;
	}

	public static WebDriver startDynamicWebDriver() {
		System.setProperty("webdriver.chrome.silentOutput", "true");
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless","--user-agent=Mozilla/5.0");
		options.addArguments("--remote-allow-origins=*");
		options.addArguments("--enable-javascript");
		WebDriverManager.chromedriver().setup();
		ChromeDriverService chromeDriverService = new ChromeDriverService.Builder().build();
		chromeDriverService.sendOutputTo(NullOutputStream.NULL_OUTPUT_STREAM);
		return new ChromeDriver(chromeDriverService, options);
	}

	public static String getContentFromDynamicPage(String url, WebDriver driver) {

		// null in unit tests for now
		if (driver == null)
			driver = startDynamicWebDriver();
		driver.get(url);
		if (url.contains("mend.io"))
			return (String) ((JavascriptExecutor) driver).executeScript("return document.getElementsByTagName('html')[0].innerHTML");
		return driver.getPageSource();
	}

	public String getContentFromUrl(String url) {
		StringBuilder response = new StringBuilder();
		BufferedReader bufferedReader;
		try {
			URL urlObject = new URL(url);
			HttpURLConnection httpURLConnection = (HttpURLConnection) urlObject.openConnection();
			httpURLConnection.setRequestMethod("GET");
			httpURLConnection.setRequestProperty("User-Agent", USER_AGENT);

			bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
			String inputLine;
			while ((inputLine = bufferedReader.readLine()) != null) {
				response.append(inputLine + "\n");
			}
			bufferedReader.close();

		} catch (SSLException e) {
			log.error(e.toString());
		} catch (SocketException e) {
			log.error(e.toString());
		} catch (IOException e) {
			log.error(e.toString());
		} catch (Exception e) {
			log.error(e.toString());
		}
		return response.toString();
	}

	/**
	 * Scrape CNNVD
	 * 
	 * @param list
	 * @return
	 */
	// public List<RawVulnerability> getCnnvdCveUpdates(List<RawVulnerability> list) {
	// 	try {
	// 		String sUrlForCveListPage = "http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=$pageno$&repairLd=";
	// 		CnnvdCveParser chinaCveParser = new CnnvdCveParser();
	// 		String dateTimeNow = UtilHelper.longDateFormat.format(new Date());
	// 		int count = list.size();
	// 		Random r = new Random(100);
	// 		// scrape first 3 pages
	// 		for (int pageIndex = 1; pageIndex < 4; pageIndex++) {
	// 			String pageLink = sUrlForCveListPage.replace("$pageno$", pageIndex + "");
	// 			log.info("Scraping CVEs from CNNVD {} ,pape # {}", pageLink, pageIndex);

	// 			String pageStr = getContentFromUrl(pageLink);
	// 			List<String> cveURLsInPage = chinaCveParser.getCveUrlListFromPage(pageStr);
	// 			for (String cveURLItem : cveURLsInPage) {
	// 				try {

	// 					String[] cveUrlParts = cveURLItem.split("=");
	// 					String cnnvdCveId = cveUrlParts[1];

	// 					log.info("Getting {} details from {}", cnnvdCveId, cveURLItem);

	// 					String cveDetailHtml = getContentFromUrl(cveURLItem);
	// 					// get CVE details
	// 					CnnvdVulnerability vuln = chinaCveParser.getCveDetailsFromPage(cveDetailHtml);

	// 					// get ref urls
	// 					List<String> refURLs = chinaCveParser.getCveReferencesFromPage(cveDetailHtml);
	// 					for (String refUrl : refURLs)
	// 						vuln.addVulnerabilitySource(refUrl);

	// 					String description = "New vulnerability from CNNVD! Details:  " + vuln.toString();
	// 					// add vuln
	// 					RawVulnerability vulnComposite = new RawVulnerability(cveURLItem, vuln.getCveId(), dateTimeNow, dateTimeNow, description);
	// 					list.add(vulnComposite);
	// 					Thread.sleep(r.nextInt(100) + 1000); // random wait
	// 				} catch (Exception e) {
	// 					log.error("Error while getting CVE details from {}, {} ", cveURLItem, e.toString());
	// 				}
	// 			}
	// 		}

	// 		log.info("Done! Scraped {} CVEs from Cnnvd! ", list.size() - count);
	// 	} catch (Exception e) {
	// 		log.error("Error scraping CNNVD! {}", e);

	// 	}
	// 	return list;

	// }

	/**
	 * Seclists CVE summaries are provided for each quarter. For example:
	 * https://seclists.org/oss-sec/2021/q2 provides CVES for the second quarter of
	 * 2021.
	 * 
	 * This methods scrapes CVEs for the current quarter
	 * 
	 * @param crawler
	 * @param list
	 * @return
	 */
	public List<RawVulnerability> getSeclistsCveUpdates(CveCrawler crawler, List<RawVulnerability> list) {
		Random r = new Random(100);
		String url = "https://seclists.org/oss-sec/{x}/q{y}";

		try {
			LocalDate myLocal = LocalDate.now();
			int year = myLocal.getYear();
			int quarter = myLocal.get(IsoFields.QUARTER_OF_YEAR);

			url = url.replace("{x}", year + "");
			url = url.replace("{y}", quarter + "");

			log.info("Getting CVES from {} ", url);
			int count = list.size();

			// summary page content
			String html = getContentFromUrl(url);
			Document doc = Jsoup.parse(html);

			// get all links in the page
			Elements elements = doc.select("a");

			// filter CVE related links
			for (Element element : elements) {
				if (element.text().contains("CVE-")) {
					String linkExt = element.attr("href");
					String pageLink = url + "/" + linkExt;

					log.info("Scraping {}", pageLink);

					// get CVE content
					html = getContentFromUrl(pageLink);
					list.addAll(crawler.parseWebPage(pageLink, html));

					Thread.sleep(r.nextInt(10) + 40); // random delay
				}
			}

			log.info("Retrieved {} CVES from {}, Total CVEs: {}", list.size() - count, url, list.size());
		} catch (Exception e) {
			log.error("Error scraping url {}, {}", url, e.toString());
		}
		return list;
	}
}
