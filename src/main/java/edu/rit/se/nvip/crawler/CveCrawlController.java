
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

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.cvereconcile.AbstractCveReconciler;
import edu.rit.se.nvip.cvereconcile.CveReconcilerFactory;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.frontier.FrontierConfiguration;
import edu.uci.ics.crawler4j.frontier.SleepycatFrontierConfiguration;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

public class CveCrawlController {

    private static final Logger logger = LogManager.getLogger(CveCrawlController.class.getSimpleName());
    static MyProperties properties = new PropertyLoader().loadConfigFile(new MyProperties());
    private final HashMap<String, ArrayList<CompositeVulnerability>> cveHashMapAll = new HashMap<>();

    public static void main(String[] args) throws Exception {

        ArrayList<String> urls = new ArrayList<>();
        ArrayList<String> whiteList = new ArrayList<>();

        File seedURLs = properties.getSeedURLSprops();
        Scanner reader = new Scanner(seedURLs);
        while (reader.hasNextLine()) {
            urls.add(reader.nextLine());
        }

        File whiteListFile = properties.getWhiteListURLSprops();
        reader = new Scanner(whiteListFile);
        while (reader.hasNextLine()) {
            whiteList.add(reader.nextLine());
        }

        long crawlStartTime = System.currentTimeMillis();
        HashMap<String, ArrayList<CompositeVulnerability>> data = new CveCrawlController().crawlwProps(urls, whiteList);
        long crawlEndTime = System.currentTimeMillis();
        logger.info("Crawler Finished\nTime: {}", crawlEndTime - crawlStartTime);

    }

    /**
     * Prepare Crawlers and begin crawling
     * return all raw vulnerability data found
     * @param urls
     * @param whiteList
     * @return
     * @throws Exception
     */
    public HashMap<String, ArrayList<CompositeVulnerability>> crawl(List<String> urls, List<String> whiteList) throws Exception {

        CrawlConfig config1 = new CrawlConfig();
        CrawlConfig config2 = new CrawlConfig();

        config1.setCrawlStorageFolder(System.getenv("NVIP_OUTPUT_DIR") + "/crawlers/crawler1");
        config2.setCrawlStorageFolder(System.getenv("NVIP_OUTPUT_DIR") + "/crawlers/crawler2");

        config1.setPolitenessDelay(Integer.parseInt(System.getenv("NVIP_CRAWLER_POLITENESS")));
        config2.setPolitenessDelay(Integer.parseInt(System.getenv("NVIP_CRAWLER_POLITENESS")));

        config1.setMaxPagesToFetch(Integer.parseInt(System.getenv("NVIP_CRAWLER_MAX_PAGES")));
        config2.setMaxPagesToFetch(Integer.parseInt(System.getenv("NVIP_CRAWLER_MAX_PAGES")));

        config1.setMaxDepthOfCrawling(Integer.parseInt(System.getenv("NVIP_CRAWLER_DEPTH")));
        config2.setMaxDepthOfCrawling(Integer.parseInt(System.getenv("NVIP_CRAWLER_DEPTH")));

        BasicURLNormalizer normalizer1 = BasicURLNormalizer.newBuilder().idnNormalization(BasicURLNormalizer.IdnNormalization.NONE).build();
        BasicURLNormalizer normalizer2 = BasicURLNormalizer.newBuilder().idnNormalization(BasicURLNormalizer.IdnNormalization.NONE).build();
        PageFetcher pageFetcher1 = new PageFetcher(config1, normalizer1);
        PageFetcher pageFetcher2 = new PageFetcher(config2, normalizer2);

		System.setProperty("webdriver.chrome.silentOutput", "true");
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless","--user-agent=Mozilla/5.0");
		options.addArguments("--remote-allow-origins=*");
		WebDriverManager.chromedriver().setup();
		WebDriver driver = new ChromeDriver(options);

		try {
			// set crawl params
			logger.info("Initializing crawl controllers...");
			CrawlController controller = getCrawlController(crawlStorageFolder, propertiesNvip.getDefaultCrawlerPoliteness());
			CrawlController delayedController = getCrawlController(crawlStorageFolder2, propertiesNvip.getDelayedCrawlerPoliteness());

			logger.info("Controllers initialized. Adding {} seed urls to crawl controller...", urls.size());
			// add seed urls
			int count = 0, countDelayed = 0;
			for (String url : urls) {
				if (UtilHelper.isDelayedUrl(url)) {
					delayedController.addSeed(url);
					countDelayed++;
				} else {
					controller.addSeed(url);
					count++;
					// logger.info("Adding seed: " + url);
				}

				if ((count + countDelayed) % 500 == 0)
					logger.info("Added {} of {} seed URLs...", (count + countDelayed), urls.size());
			}
			logger.info("{} and {} seed URLs added to the 'Default' and 'Delayed' crawlers! Initializing crawler factories...", count, countDelayed);

			// Create crawler factories.
			CrawlController.WebCrawlerFactory<CveCrawler> factory = () -> new CveCrawler(propertiesNvip, driver);
			CrawlController.WebCrawlerFactory<CveCrawler> factory2 = () -> new CveCrawler(propertiesNvip, driver);

			logger.info("Starting NVIP CVE Crawler with {} seed URLs and {} threads!", urls.size(), numberOfCrawlers);

			// Start default crawler. It is blocking!
			controller.start(factory, numberOfCrawlers);
			logger.info("Fetching CVEs from regular crawler");
			cveHashMapAll = getVulnerabilitiesFromCrawlerThreads(controller, cveHashMapAll);

			// Start delayed crawler. It is blocking!
			delayedController.start(factory2, numberOfCrawlers);
			logger.info("Fetching CVEs from delayed crawler");
			cveHashMapAll = getVulnerabilitiesFromCrawlerThreads(delayedController, cveHashMapAll);

		} catch (Exception e) {
			logger.error("Error!" + e);
		}
		return cveHashMapAll;
	}

    /**
     * Get CVEs from crawler controller and add them to cve map based on the
     * reconciliation result
     *
     * @param controller
     * @return the updated map
     */
    private synchronized HashMap<String, ArrayList<CompositeVulnerability>> getVulnerabilitiesFromCrawlerThreads(CrawlController controller) {

        List<Object> crawlersLocalData = controller.getCrawlersLocalData();
        HashMap<String, ArrayList<CompositeVulnerability>> cveDataCrawler;
        int nCrawlerID = 1;

        for (Object crawlerData : crawlersLocalData) {
            try {
                cveDataCrawler = (HashMap<String, ArrayList<CompositeVulnerability>>) crawlerData;

                for (String cveid : cveDataCrawler.keySet()) {
                        if (cveHashMapAll.get(cveid) != null) {
                            cveHashMapAll.get(cveid).addAll(cveDataCrawler.get(cveid));
                        } else {
                            cveHashMapAll.put(cveid, cveDataCrawler.get(cveid));
                        }
                }
            } catch (Exception e) {
                logger.error("Error while getting data from crawler {}\tcveDataCrawler: Error: {} ", nCrawlerID, e.toString());
            }
            nCrawlerID++;
        }

        return cveHashMapAll;
    }
}