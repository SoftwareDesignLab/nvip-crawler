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

import crawlercommons.filters.basic.BasicURLNormalizer;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.frontier.FrontierConfiguration;
import edu.uci.ics.crawler4j.frontier.SleepycatFrontierConfiguration;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;
import edu.uci.ics.crawler4j.url.SleepycatWebURLFactory;
import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CveCrawlController {
    public static final String DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0";

    private static final Logger logger = LogManager.getLogger(CveCrawlController.class.getSimpleName());
    private final HashMap<String, ArrayList<RawVulnerability>> cveHashMapAll = new HashMap<>();

    /**
     * Prepare Crawlers and begin crawling
     * return all raw vulnerability data found
     * @param urls
     * @param whiteList
     * @return
     * @throws Exception
     */
    public HashMap<String, ArrayList<RawVulnerability>> crawl(List<String> urls, List<String> whiteList,
                                                                    Map<String, Object> crawlerVars) throws Exception {

        // Prepare Crawler W/ Configuration
        CrawlConfig config1 = new CrawlConfig();
        config1.setCrawlStorageFolder((String) crawlerVars.get("outputDir"));
        config1.setPolitenessDelay((Integer) crawlerVars.get("crawlerPoliteness"));
        config1.setMaxPagesToFetch((Integer) crawlerVars.get("maxPages"));
        config1.setMaxDepthOfCrawling((Integer) crawlerVars.get("depth"));
        config1.setUserAgentString(DEFAULT_USER_AGENT);

        BasicURLNormalizer normalizer1 = BasicURLNormalizer.newBuilder().idnNormalization(BasicURLNormalizer.IdnNormalization.NONE).build();
        PageFetcher pageFetcher1 = new PageFetcher(config1, normalizer1);
        RobotstxtConfig robotstxtConfig = new RobotstxtConfig();

        FrontierConfiguration frontierConfiguration = new SleepycatFrontierConfiguration(config1);
        RobotstxtServer robotstxtServer = new RobotstxtServer(robotstxtConfig, pageFetcher1, new SleepycatWebURLFactory());
        CrawlController controller1 = new CrawlController(config1, normalizer1, pageFetcher1, robotstxtServer, frontierConfiguration);

        // Fill in seed URLs
        for (String url: urls) {
            try {
                //logger.info("ADDING {} to SEEDS", url);
                controller1.addSeed(url);
            } catch (Exception e) {
                logger.warn("WARNING: Error trying to add {} as a seed URL", url);
            }
        }

        // Crawler reporting
        String outputFile = "";
        if ((Boolean) crawlerVars.get("enableReport")) {
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
            LocalDateTime now = LocalDateTime.now();
            outputFile = crawlerVars.get("outputDir") + "/" + dtf.format(now) + ".txt";
        }

        logger.info("CURRENT CRAWL DEPTH ----> " + config1.getMaxDepthOfCrawling());

        // Setup thread factory and start crawler
        String finalOutputFile = outputFile;
        CrawlController.WebCrawlerFactory<CveCrawler> factory1 = () -> new CveCrawler(whiteList, finalOutputFile);

        controller1.startNonBlocking(factory1, (Integer) crawlerVars.get("crawlerNum"));

        controller1.waitUntilFinish();
        logger.info("Crawler 1 is finished.");

        cveHashMapAll.putAll(getVulnerabilitiesFromCrawlerThreads(controller1));

        return cveHashMapAll;
    }

    /**
     * Get CVEs from crawler controller and add them to cve map based on the
     * reconciliation result
     *
     * @param controller
     * @return the updated map
     */
    private synchronized HashMap<String, ArrayList<RawVulnerability>> getVulnerabilitiesFromCrawlerThreads(CrawlController controller) {

        List<Object> crawlersLocalData = controller.getCrawlersLocalData();
        HashMap<String, ArrayList<RawVulnerability>> cveDataCrawler;
        int nCrawlerID = 1;

        for (Object crawlerData : crawlersLocalData) {
            try {
                cveDataCrawler = (HashMap<String, ArrayList<RawVulnerability>>) crawlerData;

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