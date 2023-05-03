import crawler.CveCrawlController;
import crawler.github.GithubScraper;
import crawler.github.PyPAGithubScraper;
import db.DatabaseHelper;
import model.CompositeVulnerability;
import model.DailyRun;
import model.NvipSource;
import nvd.NvdCveController;
import utils.UtilHelper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;

public class CrawlerMain {

    private static final Logger logger = LogManager.getLogger(CrawlerMain.class);
    private static DatabaseHelper databaseHelper = null;
    private static final Map<String, Object> crawlerVars = new HashMap<>();
    private static final Map<String, Object> dataVars = new HashMap<>();

    public CrawlerMain() {
        this.prepareCrawlerVars();
        this.prepareDataVars();

        UtilHelper.initLog4j();

        // check required data directories
        checkDataDirs();

        // get sources from the seeds file or the database
        databaseHelper = DatabaseHelper.getInstance();

        if (!databaseHelper.testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }
    }

    /**
     * Update NVD table, run crawler, prepare run stats and insert
     * @param args
     */
    public static void main(String[] args) throws Exception {

        logger.info("Starting Crawler...");

        CrawlerMain crawlerMain = new CrawlerMain();
        if ((Boolean) dataVars.get("refreshNvdList")) {
            logger.info("Refreshing NVD CVE List");
            new NvdCveController().updateNvdDataTable((String) dataVars.get("nvdUrl"));
        }

        HashMap<String, CompositeVulnerability> pyCves = crawlerMain.getCvesFromPythonGitHub();

        // Crawler
        long crawlStartTime = System.currentTimeMillis();
        HashMap<String, ArrayList<CompositeVulnerability>> crawledCVEs = crawlerMain.crawlCVEs();
        long crawlEndTime = System.currentTimeMillis();
        logger.info("Crawler Finished\nTime: {}", crawlEndTime - crawlStartTime);

        // Merge CVEs found in python GitHub with CVEs that were crawled
        logger.info("Merging Python CVEs with Crawled CVEs");
        for (String pyCve: pyCves.keySet()) {
            if (crawledCVEs.containsKey(pyCve)) {
                crawledCVEs.get(pyCve).add(pyCves.get(pyCve));
            } else {
                ArrayList<CompositeVulnerability> newCveList = new ArrayList<>();
                newCveList.add(pyCves.get(pyCve));
                crawledCVEs.put(pyCve, newCveList);
            }
        }

        logger.info("Done! Preparing to insert all raw data found in this run!");

        crawlerMain.insertRawCVEs(crawledCVEs);
        logger.info("Done!");
    }

    /**
     * Iterate through each crawled CVE and add them to the raw descriptions table
     * @param crawledCves
     */
    private void insertRawCVEs(HashMap<String, ArrayList<CompositeVulnerability>> crawledCves) {
        logger.info("Inserting {} CVEs to DB", crawledCves.size());

        int insertedCVEs = 0;

        for (String cveId: crawledCves.keySet()) {
            for (CompositeVulnerability vuln: crawledCves.get(cveId)) {
                if (!databaseHelper.checkIfInRawDescriptions(vuln.getDescription())) {
                    logger.info("Inserting new raw description for CVE {} into DB" ,cveId);
                    insertedCVEs += databaseHelper.insertRawVulnerability(vuln);
                    databaseHelper.addJobForCVE(vuln.getCveId());
                }
            }
        }

        logger.info("Inserted {} raw CVE entries in rawdescriptions", insertedCVEs);

    }

    /**
     * Prepare Vars for Crawler from envvars
     * Sets defaults if envvars aren't found
     */
    private void prepareCrawlerVars() {
        String outputDir = System.getenv("NVIP_OUTPUT_DIR");
        String seedFileDir = System.getenv("NVIP_SEED_URLS");
        String whitelistFileDir = System.getenv("NVIP_WHITELIST_URLS");
        String enableGitHub = System.getenv("NVIP_ENABLE_GITHUB");
        String crawlerPoliteness = System.getenv("NVIP_CRAWLER_POLITENESS");
        String maxPages = System.getenv("NVIP_CRAWLER_MAX_PAGES");
        String depth = System.getenv("NVIP_CRAWLER_DEPTH");
        String enableReport = System.getenv("NVIP_CRAWLER_REPORT_ENABLE");
        String crawlerNum = System.getenv("NVIP_NUM_OF_CRAWLER");

        addEnvvarString(CrawlerMain.crawlerVars,"outputDir", outputDir, "output/crawlers",
                "WARNING: Crawler output path not defined in NVIP_OUTPUT_DIR, using default path: output/crawlers");

        addEnvvarString(CrawlerMain.crawlerVars,"seedFileDir", seedFileDir, "nvip_data/url-sources/nvip-seeds.txt",
                "WARNING: Crawler seed file path not defined in NVIP_SEED_URLS, using default path: " + "nvip_data/url-sources/nvip-seeds.txt");

        addEnvvarString(CrawlerMain.crawlerVars,"whitelistFileDir", whitelistFileDir, "nvip_data/url-sources/nvip-whitelist.txt",
                "WARNING: Crawler whitelist file path not defined in NVIP_WHITELIST_URLS, using default path: nvip_data/url-sources/nvip-whitelist.txt");

        addEnvvarBool(CrawlerMain.crawlerVars,"enableGitHub", enableGitHub, false,
                "WARNING: CVE GitHub Enabler not defined in NVIP_ENABLE_GITHUB, allowing CVE GitHub pull on default");

        addEnvvarInt(CrawlerMain.crawlerVars,"crawlerPoliteness", crawlerPoliteness, 3000,
                "WARNING: Crawler Politeness is not defined, using 3000 as default value",
                "NVIP_CRAWLER_POLITENESS");

        addEnvvarInt(CrawlerMain.crawlerVars,"maxPages", maxPages, 3000,
                "WARNING: Crawler Max Pages not defined in NVIP_CRAWLER_MAX_PAGES, using 3000 as default value",
                "NVIP_CRAWLER_MAX_PAGES");

        addEnvvarInt(CrawlerMain.crawlerVars,"depth", depth, 1,
                "WARNING: Crawler Depth not defined in NVIP_CRAWLER_DEPTH, using 1 as default value",
                "NVIP_CRAWLER_DEPTH");

        addEnvvarBool(CrawlerMain.crawlerVars,"enableReport", enableReport, true,
                "WARNING: Crawler Report Enabling not defined in NVIP_CRAWLER_REPORT_ENABLE, allowing report by default");

        addEnvvarInt(CrawlerMain.crawlerVars,"crawlerNum", crawlerNum, 10,
                "WARNING: Number of Crawlers not defined in NVIP_NUM_OF_CRAWLER, using 10 as default value",
                "NVIP_NUM_OF_CRAWLER");
    }


    /**
     * Prepare Vars for Data dir from envvars
     * Sets defaults if envvars aren't found
     */
    private void prepareDataVars() {
        String dataDir = System.getenv("NVIP_DATA_DIR");
        String refreshNvdList = System.getenv("NVIP_REFRESH_NVD_LIST");
        String nvdUrl = System.getenv("NVIP_NVD_URL");
        String reconcilerMethod = System.getenv("NVIP_RECONCILER_METHOD");

        addEnvvarString(CrawlerMain.dataVars,"dataDir", dataDir, "nvip_data",
                "WARNING: Data Directory not defined in NVIP_DATA_DIR, using ./nvip_data as default");
        addEnvvarBool(CrawlerMain.dataVars, "refreshNvdList", refreshNvdList, true,
                "WARNING: Refresh NVD List not defined in NVIP_REFRESH_NVD_LIST, setting true for default");
        addEnvvarString(CrawlerMain.dataVars, "nvdUrl", nvdUrl, "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>",
                "WARNING: NVD URL is not defined in NVIP_NVD_URL, setting NVD 2.0 API URL as default");
        addEnvvarString(CrawlerMain.dataVars,"reconcilerMethod", reconcilerMethod, "APACHE_OPEN_NLP",
                "WARNING: Reconciler Method not defined in NVIP_RECONCILER_METHOD, using APACHE_OPEN_NLP as default");
    }


    /**
     * Add a String to mapping of envvars
     * @param envvarMap
     * @param envvarName
     * @param envvarValue
     * @param defaultValue
     * @param warningMessage
     */
    private void addEnvvarString(Map<String, Object> envvarMap, String envvarName, String envvarValue,
                                 String defaultValue, String warningMessage) {
        if (envvarValue != null && !envvarValue.isEmpty()) {
            envvarMap.put(envvarName, envvarValue);
        } else {
            logger.warn(warningMessage);
            envvarMap.put(envvarName, defaultValue);
        }
    }

    /**
     * Add Boolean value to mapping of envvars
     * @param envvarMap
     * @param envvarName
     * @param envvarValue
     * @param defaultValue
     * @param warningMessage
     */
    private void addEnvvarBool(Map<String, Object> envvarMap, String envvarName, String envvarValue,
                               boolean defaultValue, String warningMessage) {
        if (envvarValue != null && !envvarValue.isEmpty()) {
            envvarMap.put(envvarName, Boolean.parseBoolean(envvarValue));
        } else {
            logger.warn(warningMessage);
            envvarMap.put(envvarName, defaultValue);
        }
    }

    /**
     * Add Integer to mapping of envvars
     * @param envvarMap
     * @param envvarName
     * @param envvarValue
     * @param defaultValue
     * @param warningMessage
     * @param ennvarName
     */
    private void addEnvvarInt(Map<String, Object> envvarMap, String envvarName, String envvarValue,
                              int defaultValue, String warningMessage, String ennvarName) {
        if (envvarValue != null && !envvarValue.isEmpty()) {
            try {
                envvarMap.put(envvarName, Integer.parseInt(envvarValue));
            } catch (NumberFormatException e) {
                logger.warn("WARNING: Variable: {} = {} is not an integer, using 1 as default value", ennvarName
                        , defaultValue);
                envvarMap.put(envvarName, defaultValue);
            }
        } else {
            logger.warn(warningMessage);
            envvarMap.put(envvarName, defaultValue);
        }
    }


    /**
     * check required data dirs before run
     */
    private void checkDataDirs() {
        String dataDir = (String) dataVars.get("dataDir");
        String crawlerSeeds = (String) crawlerVars.get("seedFileDir");
        String whitelistFileDir = (String) crawlerVars.get("whitelistFileDir");
        String crawlerOutputDir = (String) crawlerVars.get("outputDir");

        if (!new File(dataDir).exists()) {
            logger.error("The data dir provided does not exist, check the 'NVIP_DATA_DIR' key in the env.list file, currently configured data dir is {}", dataDir);
            System.exit(1);
        }

        if (!new File(crawlerSeeds).exists()) {
            logger.error("The crawler seeds path provided: {} does not exits!", crawlerSeeds);
            System.exit(1);
        }

        if (!new File(whitelistFileDir).exists()) {
            logger.error("The whitelist domain file path provided: {} does not exits!", whitelistFileDir);
            System.exit(1);
        }

        if (!new File(crawlerOutputDir).exists()) {
            logger.error("The crawler output dir provided: {} does not exits!", crawlerOutputDir);
            System.exit(1);
        }
    }


    /**
     * Prepares sourceURLs for NVIPs crawlers
     * @return
     */
    public List<String> grabSeedURLs() {
        List<String> urls = new ArrayList<>();
        try {
            List<NvipSource> dbsources = databaseHelper.getNvipCveSources();
            if (dbsources.isEmpty())
                logger.error("No source URLs in the database to crawl! Please make sure to include at least one source URL in the 'nvipsourceurl' table!");

            for (NvipSource nvipSource : dbsources)
                urls.add(nvipSource.getUrl());

            logger.info("Loaded {} source URLs from database!", urls.size());

            File seeds = new File((String) crawlerVars.get("seedFileDir"));
            BufferedReader seedReader = new BufferedReader(new FileReader(seeds));
            List<String> seedURLs = new ArrayList<>();
            logger.info("Loading the following urls: ");

            String url = "";
            while (url != null) {
                seedURLs.add(url);
                url = seedReader.readLine();
            }

            logger.info("Loaded {} seed URLS from {}", seedURLs.size(), seeds.getAbsolutePath());

            for (String seedURL : seedURLs) {
                if (!urls.contains(seedURL))
                    urls.add(seedURL);
            }

            logger.info("Loaded {} total seed URLs", urls.size());

        } catch (IOException e) {
            logger.error("Error while starting NVIP: {}", e.toString());
        }
        return urls;
    }


    /**
     * Crawl for CVEs from the following sources
     * GitHub
     * CVE Summary Pages
     * NVIP Source URLs in DB and seeds txt file
     *
     *
     * @return
     */
    protected HashMap<String, ArrayList<CompositeVulnerability>> crawlCVEs() throws Exception {
        /**
         * Crawl CVE from CNAs
         */
        List<String> urls = grabSeedURLs();

        logger.info("Starting the NVIP crawl process now to look for CVEs at {} locations with {} threads...",
                urls.size(), crawlerVars.get("crawlerNum"));

        CveCrawlController crawlerController = new CveCrawlController();

        ArrayList<String> whiteList = new ArrayList<>();

        File whiteListFile = new File((String) crawlerVars.get("whitelistFileDir"));
        Scanner reader = new Scanner(whiteListFile);
        while (reader.hasNextLine()) {
            String domain = reader.nextLine();
            if (domain.length() > 5) {
                logger.info("Added {} to whitelist", domain);
                whiteList.add(domain);
            }
        }

        return crawlerController.crawl(urls, whiteList, crawlerVars);
    }


    /**
     * For getting CVEs from PyPA GitHub
     * @return
     */
    protected HashMap<String, CompositeVulnerability> getCvesFromPythonGitHub() {
        // scrape CVEs from PyPA advisory database GitHub Repo
        PyPAGithubScraper pyPaScraper = new PyPAGithubScraper();
        HashMap<String, CompositeVulnerability> cvePyPAGitHub = pyPaScraper.scrapePyPAGithub();

        return cvePyPAGitHub;
    }
    /**
     * Grab CVEs from CVE GitHub
     * @return
     */
    protected HashMap<String, CompositeVulnerability> getCvesFromGitHub() {
        HashMap<String, CompositeVulnerability> cveHashMapGithub = new HashMap<>();

        if ((Boolean) crawlerVars.get("enableGitHub")) {
            logger.info("CVE Github pull enabled, scraping CVe GitHub now!");
            GithubScraper githubScraper = new GithubScraper();
            cveHashMapGithub = githubScraper.scrapeGithub();
        }

        return cveHashMapGithub;
    }


}