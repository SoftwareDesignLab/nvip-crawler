package edu.rit.se.nvip;

import com.rabbitmq.client.*;
import edu.rit.se.nvip.crawler.CveCrawlController;
import edu.rit.se.nvip.crawler.github.PyPAGithubScraper;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.UtilHelper;

import com.opencsv.CSVWriter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.lang.reflect.Modifier;

public class CrawlerMain {

    private static final Logger logger = LogManager.getLogger(CrawlerMain.class);
    private static DatabaseHelper databaseHelper = null;
    private static final Map<String, Object> crawlerVars = new HashMap<>();
    private static final Map<String, Object> dataVars = new HashMap<>();
    private static Map<String, String> sourceTypes = null;

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

        if (!this.testMQConnection()) {
            logger.error("ERROR: Failed to connect to RabbitMQ esrver on {} via port {}", dataVars.get("mqHost"), dataVars.get("mqPort"));
            System.exit(1);
        }
    }

    /**
     * Update NVD table, run crawler, prepare run stats and insert
     * @param args
     */
    public static void main(String[] args) throws Exception {

        // Initialize Crawler, check if it's in testmode
        CrawlerMain crawlerMain = new CrawlerMain();
        boolean crawlerTestMode = (boolean) crawlerVars.get("testMode");
        if (crawlerTestMode)
            logger.info("Starting Crawler IN TEST MODE using {}",
                    ((String)crawlerVars.get("seedFileDir")).split("/")[((String)crawlerVars.get("seedFileDir")).split("/").length - 1]);
        else
            logger.info("Starting Crawler...");

        // TODO: Move this to reconciler/processor
        if ((Boolean) dataVars.get("refreshNvdList")) {
            logger.info("Refreshing NVD CVE List");
//            new NvdCveController().updateNvdDataTable((String) dataVars.get("nvdUrl"));
        }

        // Get CVEs from Python GitHub
        HashMap<String, RawVulnerability> pyCves = new HashMap<>();
        if (!crawlerTestMode)
             pyCves = crawlerMain.getCvesFromPythonGitHub();

        // Crawler
        long crawlStartTime = System.currentTimeMillis();
        HashMap<String, ArrayList<RawVulnerability>> crawledCVEs = crawlerMain.crawlCVEs();
        long crawlEndTime = System.currentTimeMillis();
        logger.info("Crawler Finished\nTime: {} seconds", (crawlEndTime - crawlStartTime) / 1000.0);

        // Merge CVEs found in python GitHub with CVEs that were crawled
        if (!crawlerTestMode) {
            logger.info("Merging Python CVEs with Crawled CVEs");
            for (String pyCve: pyCves.keySet()) {
                if (crawledCVEs.containsKey(pyCve)) {
                    crawledCVEs.get(pyCve).add(pyCves.get(pyCve));
                } else {
                    ArrayList<RawVulnerability> newCveList = new ArrayList<>();
                    newCveList.add(pyCves.get(pyCve));
                    crawledCVEs.put(pyCve, newCveList);
                }
            }
        }

        // Update the source types for the found CVEs and insert new entries into the rawdescriptions table
        updateSourceTypes(crawledCVEs);

        logger.info("Outputting CVEs to a CSV and JSON");
        int linesWritten = cvesToCsv(crawledCVEs);
        logger.info("Wrote {} lines to {}", linesWritten, (String)crawlerVars.get("testOutputDir")+"/test_output.csv");
        cvesToJson(crawledCVEs);
        logger.info("Done!");

        // Output results in testmode
        // Store raw data in DB otherwise
        if (crawlerTestMode) {
            logger.info("CVEs Found: {}", crawledCVEs.size());
            for (String cveId: crawledCVEs.keySet()) {
                logger.info("CVE: {}:\n", cveId);
                for (RawVulnerability vuln: crawledCVEs.get(cveId)) {
                    String description = vuln.getDescription().length() > 100 ? vuln.getDescription().substring(0, 100) + "...": vuln.getDescription();
                    logger.info("[{} | {}]\n", vuln.getSourceURL(), description);
                }
            }
        } else {
            // Update the source types for the found CVEs and insert new entries into the rawdescriptions table
            logger.info("Done! Preparing to insert all raw data found in this run!");
            crawlerMain.insertRawCVEsAndPrepareMessage(crawledCVEs);
            logger.info("Raw data inserted and Message sent successfully!");
        }

        logger.info("Done!");
    }

    /**
     * Prepare Vars for Crawler from envvars
     * Sets defaults if envvars aren't found
     */
    private void prepareCrawlerVars() {
        String outputDir = System.getenv("NVIP_OUTPUT_DIR");
        String seedFileDir = System.getenv("NVIP_SEED_URLS");
        String whitelistFileDir = System.getenv("NVIP_WHITELIST_URLS");
        String sourceTypeFileDir = System.getenv("NVIP_SOURCE_TYPES");
        String enableGitHub = System.getenv("NVIP_ENABLE_GITHUB");
        String crawlerPoliteness = System.getenv("NVIP_CRAWLER_POLITENESS");
        String maxPages = System.getenv("NVIP_CRAWLER_MAX_PAGES");
        String depth = System.getenv("NVIP_CRAWLER_DEPTH");
        String enableReport = System.getenv("NVIP_CRAWLER_REPORT_ENABLE");
        String crawlerNum = System.getenv("NVIP_NUM_OF_CRAWLER");
        String testMode = System.getenv("NVIP_CRAWLER_TEST_MODE");
        String testOutputDir = System.getenv("NVIP_TEST_OUTPUT_DIR");

        addEnvvarString(CrawlerMain.crawlerVars,"outputDir", outputDir, "output/crawlers",
                "WARNING: Crawler output path not defined in NVIP_OUTPUT_DIR, using default path: output/crawlers");

        addEnvvarString(CrawlerMain.crawlerVars,"seedFileDir", seedFileDir, "crawler/resources/url-sources/nvip-seeds.txt",
                "WARNING: Crawler seed file path not defined in NVIP_SEED_URLS, using default path: " + "resources/url-sources/nvip-seeds.txt");

        addEnvvarString(CrawlerMain.crawlerVars,"whitelistFileDir", whitelistFileDir, "crawler/resources/url-sources/nvip-whitelist.txt",
                "WARNING: Crawler whitelist file path not defined in NVIP_WHITELIST_URLS, using default path: resources/url-sources/nvip-whitelist.txt");

        addEnvvarString(CrawlerMain.crawlerVars,"sourceTypeFileDir", sourceTypeFileDir, "crawler/resources/url-sources/nvip-source-types.txt",
                "WARNING: Crawler whitelist file path not defined in NVIP_SOURCE_TYPES, using default path: resources/url-sources/nvip-source-types.txt");

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

        addEnvvarBool(CrawlerMain.crawlerVars,"testMode", testMode, false,
                "WARNING: Crawler Test Mode not defined in NVIP_CRAWLER_TEST_MODE, using false as default value");

        addEnvvarString(CrawlerMain.crawlerVars,"testOutputDir", testOutputDir, "output",
                "WARNING: Crawler test output dir path not defined in NVIP_TEST_OUTPUT_DIR, using default path: output");
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
        String mqHost = System.getenv("RABBIT_HOST");
        String mqPort = System.getenv("RABBIT_PORT");
        String mqQueueName = System.getenv("RABBIT_QUEUE_NAME");

        addEnvvarString(CrawlerMain.dataVars,"dataDir", dataDir, "nvip_data",
                "WARNING: Data Directory not defined in NVIP_DATA_DIR, using ./nvip_data as default");
        addEnvvarBool(CrawlerMain.dataVars, "refreshNvdList", refreshNvdList, true,
                "WARNING: Refresh NVD List not defined in NVIP_REFRESH_NVD_LIST, setting true for default");
        addEnvvarString(CrawlerMain.dataVars, "nvdUrl", nvdUrl, "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>",
                "WARNING: NVD URL is not defined in NVIP_NVD_URL, setting NVD 2.0 API URL as default");
        addEnvvarString(CrawlerMain.dataVars,"reconcilerMethod", reconcilerMethod, "APACHE_OPEN_NLP",
                "WARNING: Reconciler Method not defined in NVIP_RECONCILER_METHOD, using APACHE_OPEN_NLP as default");

        addEnvvarString(CrawlerMain.dataVars,"mqHost", mqHost, "localhost",
                "WARNING: MQ Host not defined in RABBIT_HOST, using 'localhost' as default");
        addEnvvarInt(CrawlerMain.dataVars,"mqPort", mqPort, 5762,
                "WARNING: MQ Port not defined in RABBIT_PORT, using 5762 as default",
                "RABBIT_PORT");
        addEnvvarString(CrawlerMain.dataVars,"mqQueueName", mqQueueName, "raw_data_queue",
                "WARNING: MQ Queue Name not defined in RABBIT_QUEUE_NAME, using 'raw_data_queue' as default");

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
        String testOutputDir = (String) crawlerVars.get("testOutputDir");

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

        if (!new File(testOutputDir).exists()) {
            logger.error("The crawler output dir provided: {} does not exits!", testOutputDir);
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
            File seeds = new File((String) crawlerVars.get("seedFileDir"));
            BufferedReader seedReader = new BufferedReader(new FileReader(seeds));
            // List<String> seedURLs = new ArrayList<>();
            logger.info("Loading the following urls: ");

            String url = "";
            while (url != null) {
                urls.add(url);
                url = seedReader.readLine();
            }

            // logger.info("Loaded {} seed URLS from {}", seedURLs.size(), seeds.getAbsolutePath());

            // for (String seedURL : seedURLs) {
            //     if (!urls.contains(seedURL))
            //         urls.add(seedURL);
            // }

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
    protected HashMap<String, ArrayList<RawVulnerability>> crawlCVEs() throws Exception {
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
                //logger.info("Added {} to whitelist", domain);
                whiteList.add(domain);
            }
        }

        return crawlerController.crawl(urls, whiteList, crawlerVars);
    }


    /**
     * For getting CVEs from PyPA GitHub
     * @return
     */
    protected HashMap<String, RawVulnerability> getCvesFromPythonGitHub() {
        // scrape CVEs from PyPA advisory database GitHub Repo
        PyPAGithubScraper pyPaScraper = new PyPAGithubScraper();
        HashMap<String, RawVulnerability> cvePyPAGitHub = pyPaScraper.scrapePyPAGithub();

        return cvePyPAGitHub;
    }

    private static void cvesToJson(HashMap<String, ArrayList<RawVulnerability>> crawledCVEs){
        GsonBuilder builder = new GsonBuilder(); 
        builder.setPrettyPrinting(); 
        StringBuilder sb = new StringBuilder();

        Gson gson = builder.excludeFieldsWithModifiers(Modifier.FINAL).create();
        String json = gson.toJson(crawledCVEs);
        // logger.info(json);

        try{
            String filepath = (String) crawlerVars.get("testOutputDir") + "/test_output.json";
            File file = new File(filepath);
            BufferedWriter output = new BufferedWriter(new FileWriter(file));          
            output.write(json);
            output.close();
        } catch (IOException e) {
            logger.error("Exception while writing list to JSON file!" + e);
        }

    }

    private static int cvesToCsv(HashMap<String, ArrayList<RawVulnerability>> crawledCVEs){
        int lineCount = 0;
        CSVWriter writer = null;
        String filepath = (String) crawlerVars.get("testOutputDir") + "/test_output.csv";

        try {
            logger.info("Writing to CSV: {}", filepath);
            FileWriter fileWriter = new FileWriter(filepath, false);
            writer = new CSVWriter(fileWriter, '\t', CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);

            String[] columnHeaders = {"CVE ID", "Raw Description", "Created Date", "Published Date", "Last Modified Date", "Source URL", "Source Type"};
            writer.writeNext(columnHeaders, false);

            for (ArrayList<RawVulnerability> vulnList : crawledCVEs.values()) {
                for (RawVulnerability vuln : vulnList) {
                    String desc = vuln.getDescription().replace("\r\n", ". ").replace("\n", ". ").replace("\r", ". ").replace("\t", " ");
                    String[] data = {vuln.getCveId(), desc, vuln.getCreateDate(), vuln.getPublishDate(), 
                        vuln.getLastModifiedDate(), vuln.getSourceURL(), vuln.getSourceType()};
                    writer.writeNext(data, false);
                    lineCount++;
                }
            }

            writer.close();
        } catch (IOException e) {
            logger.error("Exception while writing list to CSV file!" + e);
            return 0;
        }

        return lineCount;
    }

    /**
     * Util method used for mapping source types to each CVE source
     */
    private static void createSourceTypeMap(){
        if (sourceTypes == null)
            sourceTypes = new HashMap<>();
        try {
            // Read in source type mapping file
            File sources = new File((String) crawlerVars.get("sourceTypeFileDir"));
            BufferedReader sourceReader = new BufferedReader(new FileReader(sources));

            // Map each source URL to its source type and fill in the sourceTypes hashmap
            String source = "";
            while (source != null) {
                String[] tokens = source.split(" ");
                if (tokens.length < 2)
                    logger.warn("Source {} is not formatted correctly", source);
                else
                    sourceTypes.put(tokens[0], tokens[1]);
                source = sourceReader.readLine();
            }

            logger.info("Loaded {} total sources/types", sourceTypes.size());

        } catch (IOException e) {
            logger.error("Error while starting NVIP: {}", e.toString());
        }
    }

    /**
     * Util method used for updating source types for found CVEs
     * @param crawledCves
     */
    private static void updateSourceTypes(HashMap<String, ArrayList<RawVulnerability>> crawledCves){
        // Prepare source types mapping
        createSourceTypeMap();

        // For each raw CVE,
        for (String cveId: crawledCves.keySet()) {
            for (RawVulnerability vuln: crawledCves.get(cveId)) {
                if(vuln.getSourceURL() == null || vuln.getSourceURL().equals("")){
                    vuln.setSourceType("other");
                    continue;
                }

                // Set source type if the URL is listed in the types file
                // Otherwise, just set the source type to 'other'
                try{
                    URL sourceURL = new URL(vuln.getSourceURL());
                    vuln.setSourceType(sourceTypes.get(sourceURL.getHost()));
                }
                catch(MalformedURLException e){
                    logger.warn("Bad sourceURL {}: {}", vuln.getSourceURL(), e.toString());
                }

                if(vuln.getSourceType() == null){
                    vuln.setSourceType("other");
                }
            }
        }
    }

    /**
     * Iterate through each crawled CVE and add them to the raw descriptions table
     * @param crawledCves
     */
    private void insertRawCVEsAndPrepareMessage(HashMap<String, ArrayList<RawVulnerability>> crawledCves) {
        logger.info("Inserting {} CVEs to DB", crawledCves.size());
        int insertedCVEs = 0;
        JSONArray cveArray = new JSONArray();

        for (String cveId: crawledCves.keySet()) {
            for (RawVulnerability vuln: crawledCves.get(cveId)) {
                // check if the data is already in the DB before inserting.
                if (!databaseHelper.checkIfInRawDescriptions(vuln.getCveId(), vuln.getDescription())) {
                    //logger.info("Inserting new raw description for CVE {} into DB" ,cveId);
                    insertedCVEs += databaseHelper.insertRawVulnerability(vuln);
                    cveArray.add(vuln.getCveId());
                }
            }
        }

        logger.info("Inserted {} raw CVE entries in rawdescriptions", insertedCVEs);
        logger.info("Notifying Reconciler to reconciler {} new raw data entries", insertedCVEs);

        // Prepare the message and send it to the MQ server for Reconciler to pick up
        // Sends a JSON object with an array of CVE IDs that require reconciliation
        JSONObject messageBody = new JSONObject();
        messageBody.put("cves", cveArray);

        try {
            // Create a connection to the RabbitMQ server and create the channel
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost(dataVars.get("mqHost") + "");
            factory.setPort((int) dataVars.get("mqPort"));
            Connection connection = factory.newConnection();
            Channel channel = connection.createChannel();

            // Declare a queue and send the message
            String queueName = dataVars.get("mqQueueName") + "";
            channel.queueDeclare(queueName, false, false, false, null);
            logger.info("Queue '{}' created successfully.", queueName);
            channel.basicPublish("", queueName, null, cveArray.toJSONString().getBytes());
            logger.info("Message to Reconciler sent successfully.");

            channel.close();
            connection.close();
        } catch (Exception ex) {
            logger.error("ERROR: Failed to send message to MQ server on {} via port {}", dataVars.get("mqHost"),
                    dataVars.get("mqPort"));
        }
    }

    private boolean testMQConnection() {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(dataVars.get("mqHost") + "");
        factory.setPort((int) dataVars.get("mqPort"));
        try (Connection connection = factory.newConnection()){
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
