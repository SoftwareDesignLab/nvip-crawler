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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.*;
import java.util.stream.Collectors;

import edu.rit.se.nvip.crawler.github.PyPAGithubScraper;

import edu.rit.se.nvip.exploit.ExploitIdentifier;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.patchfinder.JGitCVEPatchDownloader;
import edu.rit.se.nvip.patchfinder.PatchFinder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.crawler.CveCrawlController;
import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.crawler.github.GithubScraper;
import edu.rit.se.nvip.cveprocess.CveLogDiff;
import edu.rit.se.nvip.cveprocess.CveProcessor;
import edu.rit.se.nvip.cvereconcile.AbstractCveReconciler;
import edu.rit.se.nvip.cvereconcile.CveReconcilerFactory;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.DbParallelProcessor;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.CompositeVulnerability.CveReconcileStatus;
import edu.rit.se.nvip.model.DailyRun;
import edu.rit.se.nvip.model.NvipSource;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.productnameextractor.AffectedProductIdentifier;
import edu.rit.se.nvip.utils.CveUtils;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.NlpUtil;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 *
 * NVIP Main class, crawl CVEs from the provided source url list file
 *
 * if you want to run nvip locally provide the path of the file that includes
 * source urls from the command line:
 *
 * Otherwise, it will load the urls from the database
 *
 *
 * @author axoeec
 *
 */
public class NVIPMain {
	private static final Logger logger = LogManager.getLogger(NVIPMain.class);
	private static DatabaseHelper databaseHelper = null;
	private static MyProperties properties = null;
	private static final Map<String, Object> crawlerVars = new HashMap<>();
	private static final Map<String, Object> dataVars = new HashMap<>();

	private static final Map<String, Object> characterizationVars = new HashMap<>();
	private static final Map<String, Object> exploitVars = new HashMap<>();
	private static final Map<String, Object> patchfinderVars = new HashMap<>();
	private static final Map<String, Object> emailVars = new HashMap<>();

	/**
	 * Main function
	 * this is how the NVIP backend runs as of now
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		// start nvip
		NVIPMain nvipMain = new NVIPMain();
		CveLogDiff cveLogger = new CveLogDiff(properties);
		List<String> urls = nvipMain.grabSeedURLs();
		if ((Boolean) dataVars.get("refreshNvdList")) {
			logger.info("Refreshing NVD CVE List");
			String filepath = dataVars.get("dataDir") + "/nvd-cve.csv";
			new NvdCveController().pullNvdCve(filepath);
		}

		// Crawler
		long crawlStartTime = System.currentTimeMillis();
		HashMap<String, CompositeVulnerability> crawledCVEs = nvipMain.crawlCVEs(urls);
		long crawlEndTime = System.currentTimeMillis();
		logger.info("Crawler Finished\nTime: {}", crawlEndTime - crawlStartTime);

		// Process and Reconcile
		HashMap<String, List<Object>> cveListMap = nvipMain.processCVEs(crawledCVEs);
		List<CompositeVulnerability> crawledVulnerabilityList = nvipMain.reconcileCVEs(cveListMap);

		// Characterize
		crawledVulnerabilityList = nvipMain.characterizeCVEs(crawledVulnerabilityList);

		DailyRun dailyRunStats = new DailyRun(UtilHelper.longDateFormat.format(new Date()),
				(float) ((crawlEndTime - crawlStartTime) / (1000.0 * 60)), crawledVulnerabilityList.size(), cveListMap.get("nvd").size(),
				cveListMap.get("mitre").size(), cveListMap.get("nvd-mitre").size());

		dailyRunStats.calculateAddedUpdateCVEs(crawledVulnerabilityList);

		logger.info("Calculating Average Time Gaps...");
		dailyRunStats.calculateAvgTimeGaps(crawledVulnerabilityList);

		databaseHelper.insertDailyRun(dailyRunStats);
		logger.info("Run @ {}\nSummary:\nTotal CVEs found from this run: {}\nTotal CVEs not in NVD: {}" +
						"\nTotal CVEs not in Mitre: {}\nTotal CVEs not in both: {}\nTotal CVEs Added: {}\nTotal CVEs Updated: {}" +
						"\nAvg NVD Time Gap: {}\n Avg MITRe Time Gap: {}\n", dailyRunStats.getRunDateTime(),
				dailyRunStats.getTotalCveCount(), dailyRunStats.getNotInNvdCount(), dailyRunStats.getNotInMitreCount(),
				dailyRunStats.getNotInBothCount(), dailyRunStats.getAddedCveCount(), dailyRunStats.getUpdatedCveCount(),
				dailyRunStats.getAvgTimeGapNvd(), dailyRunStats.getAvgTimeGapMitre());

		// Prepare stats and Store found CVEs in DB
		int runId = databaseHelper.getLatestRunId();
		nvipMain.storeCVEs(crawledVulnerabilityList, runId);

		// log .csv files
		logger.info("Creating output CSV files...");
		cveLogger.logAndDiffCVEs(crawlStartTime, crawlEndTime, cveListMap, cveListMap.size());

		// Exploit Collection
		if ((boolean) exploitVars.get("exploitFinderEnabled")) {
			logger.info("Identifying exploits for {} exploits...", crawledVulnerabilityList.size());
			ExploitIdentifier exploitIdentifier = new ExploitIdentifier(crawledVulnerabilityList, databaseHelper, (String) dataVars.get("dataDir"),
					(String) exploitVars.get("exploitDBURL"));
			exploitIdentifier.identifyAndStoreExploits();
		}

		//Patch Collection
		nvipMain.spawnProcessToIdentifyAndStoreAffectedReleases(crawledVulnerabilityList);

		if (Boolean.parseBoolean(System.getenv("PATCHFINDER_ENABLED"))) {
			// Parse for patches and store them in the database
			PatchFinder patchFinder = new PatchFinder();
			Map<String, ArrayList<String>> cpes = databaseHelper.getCPEsAndCVE();
			patchFinder.parseMassURLs(cpes);
			JGitCVEPatchDownloader jGitCVEPatchDownloader = new JGitCVEPatchDownloader();
			// repos will be cloned to patch-repos directory, multi-threaded 6 threads.
			jGitCVEPatchDownloader.parseMulitThread("patch-repos", 6);
		}

		logger.info("Done!");
	}


	/**
	 * NVIP Main Constructor
	 * Load properties and prepare initial data
	 */
	public NVIPMain() {
		// load properties file

		this.prepareCrawlerVars();
		this.prepareDataVars();
		this.prepareCharacterizationVars();
		this.prepareExploitFinderVars();
		this.preparePatchFinderVars();
		this.prepareEmailVars();

		properties = new MyProperties();
		properties = new PropertyLoader().loadConfigFile(properties);

		UtilHelper.initLog4j(properties);

		// check required data directories
		checkDataDirs();

		// get sources from the seeds file or the database
		databaseHelper = DatabaseHelper.getInstance();

		if (!databaseHelper.testDbConnection()) {
			String configFile = "src/main/resources/db-" + properties.getDatabaseType() + ".properties";
			logger.error("Error in database connection! Please check if the database configured in {} is up and running!", configFile);
			System.exit(1);
		}

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

		addEnvvarString(NVIPMain.crawlerVars,"outputDir", outputDir, "output/crawlers",
				"WARNING: Crawler output path not defined in NVIP_OUTPUT_DIR, using default path: output/crawlers");

		addEnvvarString(NVIPMain.crawlerVars,"seedFileDir", seedFileDir, "nvip_data/url-sources/nvip-seeds.txt",
				"WARNING: Crawler seed file path not defined in NVIP_SEED_URLS, using default path: " + "nvip_data/url-sources/nvip-seeds.txt");

		addEnvvarString(NVIPMain.crawlerVars,"whitelistFileDir", whitelistFileDir, "nvip_data/url-sources/nvip-whitelist.txt",
				"WARNING: Crawler whitelist file path not defined in NVIP_WHITELIST_URLS, using default path: nvip_data/url-sources/nvip-whitelist.txt");

		addEnvvarBool(NVIPMain.crawlerVars,"enableGitHub", enableGitHub, false,
				"WARNING: CVE GitHub Enabler not defined in NVIP_ENABLE_GITHUB, allowing CVE GitHub pull on default");

		addEnvvarInt(NVIPMain.crawlerVars,"crawlerPoliteness", crawlerPoliteness, 3000,
				"WARNING: Crawler Politeness is not defined, using 3000 as default value",
				"NVIP_CRAWLER_POLITENESS");

		addEnvvarInt(NVIPMain.crawlerVars,"maxPages", maxPages, 3000,
				"WARNING: Crawler Max Pages not defined in NVIP_CRAWLER_MAX_PAGES, using 3000 as default value",
				"NVIP_CRAWLER_MAX_PAGES");

		addEnvvarInt(NVIPMain.crawlerVars,"depth", depth, 1,
				"WARNING: Crawler Depth not defined in NVIP_CRAWLER_DEPTH, using 1 as default value",
				"NVIP_CRAWLER_DEPTH");

		addEnvvarBool(NVIPMain.crawlerVars,"enableReport", enableReport, true,
				"WARNING: Crawler Report Enabling not defined in NVIP_CRAWLER_REPORT_ENABLE, allowing report by default");

		addEnvvarInt(NVIPMain.crawlerVars,"crawlerNum", crawlerNum, 10,
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
		String reconcilerMethod = System.getenv("NVIP_RECONCILER_METHOD");

		addEnvvarString(NVIPMain.dataVars,"dataDir", dataDir, "nvip_data",
				"WARNING: Data Directory not defined in NVIP_DATA_DIR, using ./nvip_data as default");
		addEnvvarBool(NVIPMain.dataVars, "refreshNvdList", refreshNvdList, true,
				"WARNING: Refresh NVD List not defined in NVIP_REFRESH_NVD_LIST, setting true for default");
		addEnvvarString(NVIPMain.dataVars,"reconcilerMethod", reconcilerMethod, "APACHE_OPEN_NLP",
				"WARNING: Reconciler Method not defined in NVIP_RECONCILER_METHOD, using APACHE_OPEN_NLP as default");
	}

	private void prepareCharacterizationVars() {
		String cveCharacterizationLimit = System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT");

		addEnvvarInt(NVIPMain.characterizationVars, "cveCharacterizationLimit", cveCharacterizationLimit, 5000,
				"WARNING: CVE Characterization limit not determined at NVIP_CVE_CHARACTERIZATION_LIMIT, using 5000 as default",
				"NVIP_CVE_CHARACTERIZATION_LIMIT");

	}

	/**
	 * Prepare Vars for Exploit Finder from envvars
	 * Sets defaults if envvars aren't found
	 */
	private void prepareExploitFinderVars() {
		String exploitFinderEnabled = System.getenv("EXPLOIT_FINDER_ENABLED");
		String exploitDBURL = System.getenv("EXPLOIT_DB_URL");

		addEnvvarBool(NVIPMain.exploitVars, "exploitFinderEnabled", exploitFinderEnabled, true,
				"WARNING: Exploit Finder Enabler not defined in EXPLOIT_FINDER_ENABLED, enabling by default");

		addEnvvarString(NVIPMain.exploitVars, "exploitDBURL", exploitDBURL, "https://gitlab.com/exploit-database/exploitdb",
				"WARNING: ExploitDB Git URL not defined in EXPLOIT_DB_URL, setting to https://gitlab.com/exploit-database/exploitdb " +
						"by default");

	}

	/**
	 * Prepare Vars for Patch Finder from envvars
	 * Sets defaults if envvars aren't found
	 */
	private void preparePatchFinderVars() {
		String enablePatchFinder = System.getenv("PATCHFINDER_ENABLED");
		String patchSourceLimit = System.getenv("PATCHFINDER_SOURCE_LIMIT");
		String patchfinderMaxThreads = System.getenv("PATCHFINDER_MAX_THREADS");

		addEnvvarBool(NVIPMain.patchfinderVars,"enablePatchFinder", enablePatchFinder, true,
				"WARNING: PatchFinder Enabling not defined in PATCHFINDER_ENABLED, allowing patchfinder by default");

		addEnvvarInt(NVIPMain.patchfinderVars,"patchSourceLimit", patchSourceLimit, 10,
				"WARNING: PatchFinder Source Limit not defined in PATCHFINDER_SOURCE_LIMIT, using 10 as default value",
				"PATCHFINDER_SOURCE_LIMIT");

		addEnvvarInt(NVIPMain.patchfinderVars,"patchfinderMaxThreads", patchfinderMaxThreads, 10,
				"WARNING: Maximum PatchFinder Threads not defined in PATCHFINDER_MAX_THREADS, using 10 as default value",
				"PATCHFINDER_MAX_THREADS");
	}

	/**
	 * Prepare Vars for Email Service from envvars
	 * Sets defaults if envvars aren't found
	 */
	private void prepareEmailVars() {
		String emailUser = System.getenv("NVIP_EMAIL_USER");
		String emailPassword = System.getenv("NVIP_EMAIL_PASSWORD");
		String emailFromAddress = System.getenv("NVIP_EMAIL_FROM");
		String emailPort = System.getenv("NVIP_EMAIL_PORT");
		String emailHost = System.getenv("NVIP_EMAIL_HOST");
		String emailMessageUrl = System.getenv("NVIP_EMAIL_MESSAGE_URL");

		addEnvvarString(NVIPMain.emailVars, "emailUser", emailUser, "",
				"WARNING: No Email User provided in NVIP_EMAIL_USER, disabling email on default");

		addEnvvarString(NVIPMain.emailVars, "emailPassword", emailPassword, "",
				"WARNING: No Email Password provided in NVIP_EMAIL_PASSWORD, disabling email on default");

		addEnvvarString(NVIPMain.emailVars, "emailFromAddress", emailFromAddress, "",
				"WARNING: No Email From Address provided in NVIP_EMAIL_FROM, disabling email on default");

		addEnvvarInt(NVIPMain.emailVars, "emailPort", emailPort, -1,
				"WARNING: No Email Port provided in NVIP_EMAIL_PORT, disabling email on default",
				"NVIP_EMAIL_PORT");

		addEnvvarString(NVIPMain.emailVars, "emailHost", emailHost, "",
				"WARNING: No Email Host provided in NVIP_EMAIL_HOST, disabling email on default");

		addEnvvarString(NVIPMain.emailVars, "emailMessageUrl", emailMessageUrl, "",
				"WARNING: No Email Message URL Provided in NVIP_EMAIL_MESSAGE_URL, disabling email " +
						"message links on default");
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
	 * Print found properties to verify they're correct
	 * @param prop
	 */
	public void printProperties(MyProperties prop) {
		StringBuilder sb = new StringBuilder();

		for (Object key : prop.keySet()) {
			sb.append(String.format("%-40s", key)).append("\t->\t").append(prop.getProperty(key.toString())).append("\n");
		}

		logger.info("\n*** Parameters from Config File *** \n{}", sb.toString());
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

		String characterizationDir = dataDir + "/characterization";
		if (!new File(characterizationDir).exists()) {
			logger.error("The data dir provided does not include training data for CVE characterization! Make sure you have the directory {} that includes required training data for CVE characterization!", characterizationDir);
			System.exit(1);
		}

		String cvssDir = dataDir + "/cvss";
		if (!new File(cvssDir).exists()) {
			logger.error("The data dir provided does not include CVSS Vectors for CVSS Scoring! Make sure you have the directory {} and the required content!", cvssDir);
			System.exit(1);
		}

		String productExtrcationDir = dataDir + "/productnameextraction";
		if (!new File(productExtrcationDir).exists()) {
			logger.error("The data dir provided does not include training data for CPE extraction! Make sure you have the directory {}!", productExtrcationDir);
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
	 * Crawl for CVEs from the following sources
	 * GitHub
	 * CVE Summary Pages
	 * NVIP Source URLs in DB and seeds txt file
	 *
	 * TODO: Break this up into separate functions
	 * 	github, quick, and main
	 *
	 * @param urls
	 * @return
	 */
	protected HashMap<String, CompositeVulnerability> crawlCVEs(List<String> urls) throws Exception {
		/**
		 * scrape CVEs from CVE Automation Working Group Git Pilot (CVEProject.git)
		 */

		HashMap<String, CompositeVulnerability> cveHashMapGithub = new HashMap<>();

		if ((Boolean) crawlerVars.get("enableGitHub")) {
			logger.info("CVE Github pull enabled, scraping CVe GitHub now!");
			GithubScraper githubScraper = new GithubScraper();
			cveHashMapGithub = githubScraper.scrapeGithub();
		}

		// scrape CVEs from PyPA advisory database GitHub Repo
		PyPAGithubScraper pyPaScraper = new PyPAGithubScraper();
		HashMap<String, CompositeVulnerability> cvePyPAGitHub = pyPaScraper.scrapePyPAGithub();

		logger.info("Merging {} PyPA CVEs with {} found GitHub CVEs\n", cvePyPAGitHub.size(), cveHashMapGithub.size());
		cveHashMapGithub.putAll(cvePyPAGitHub);

		/**
		 * Scrape CVE summary pages (frequently updated CVE providers)
		 */
		int countCVEsNotInMitreGithub = 0;
		QuickCveCrawler crawler = new QuickCveCrawler();
		List<CompositeVulnerability> list = crawler.getCVEsfromKnownSummaryPages();
		for (CompositeVulnerability vuln : list)
			if (!cveHashMapGithub.containsKey(vuln.getCveId())) {
				countCVEsNotInMitreGithub++;
				cveHashMapGithub.put(vuln.getCveId(), vuln);
			}
		logger.info("{} of {} CVEs found in the CNA summary pages did not exist in the Mitre GitHub repo.", countCVEsNotInMitreGithub, list.size());

		/**
		 * Crawl CVE from CNAs
		 */
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

		HashMap<String, ArrayList<CompositeVulnerability>> cveHashMapScrapedFromCNAs = crawlerController.crawl(urls, whiteList, crawlerVars);

		return mergeCVEsDerivedFromCNAsAndGit(cveHashMapGithub, list, cveHashMapScrapedFromCNAs);
	}

	/**
	 * Merge CVES derived from the Git repo and CNAs. If a CVE exists at both
	 * sources, take the one at Git (overwrite). If a CVE exists at both sources and
	 * is reserved at Git, then, add a note to the description to indicate that.
	 *
	 * The description of a reserved CVE on MITRE: ** RESERVED ** This candidate has
	 * been reserved by an organization or individual that will use it when
	 * announcing a new security problem. When the candidate has been publicized,
	 * the details for this candidate will be provided.
	 *
	 * @param cveHashMapGithub
	 * @param cveHashMapScrapedFromCNAs
	 * @return
	 */
	public HashMap<String, CompositeVulnerability> mergeCVEsDerivedFromCNAsAndGit(HashMap<String, CompositeVulnerability> cveHashMapGithub, List<CompositeVulnerability> list,
																				  HashMap<String, ArrayList<CompositeVulnerability>> cveHashMapScrapedFromCNAs) {
		logger.info("Merging {} scraped CVEs with {} Github", cveHashMapScrapedFromCNAs.size(), list.size() + cveHashMapGithub.size());
		final String reservedStr = "** RESERVED **";
		HashMap<String, CompositeVulnerability> cveHashMapAll = new HashMap<>(); // merged CVEs

		// Just processes the first description found for each CVE
		// TODO: Figure out how to merge ALL found descriptions into one.
		//  Not sure if the current model helps with that (Maybe use GPT?)
		for (String cveId: cveHashMapScrapedFromCNAs.keySet()) {
			cveHashMapAll.put(cveId, cveHashMapScrapedFromCNAs.get(cveId).get(0));
		}

		// include all CVEs from CNAs
		NlpUtil nlpUtil = new NlpUtil();

		int cveCountReservedInGit = 0;
		int cveCountFoundOnlyInGit = 0;
		// iterate over CVEs from Git
		for (String cveId : cveHashMapGithub.keySet()) {
			// If a CVE derived from Git does not exist among the CVEs derived from CNAs,
			// then include it as is.
			CompositeVulnerability vulnGit = cveHashMapGithub.get(cveId);
			if (!cveHashMapAll.containsKey(cveId)) {
				cveHashMapAll.put(cveId, vulnGit);
				cveCountFoundOnlyInGit++;
			} else {
				/**
				 * Git CVE already exists among CVEs derived from CNAs, then look at
				 * descriptions!
				 * */

				CompositeVulnerability vulnCna = cveHashMapAll.get(cveId);
				String newDescr;

				if (CveUtils.isCveReservedEtc(vulnGit.getDescription())) {
					/**
					 * CVE is reserved/rejected etc in Mitre but nvip found a description for it.
					 * TODO: We need to find a better way to merge the found descriptions
					 * 	instead of just running each of them through NLP one-by-one
					 * 	Is it possible for us to batch process the found descriptions into a single NLP?
					 * */

					newDescr = reservedStr + " - NVIP Description: " + vulnCna.getDescription();
					cveCountReservedInGit++;

					// did we find garbage or valid description?
					if (nlpUtil.sentenceDetect(vulnCna.getDescription()) != null)
						vulnCna.setFoundNewDescriptionForReservedCve(true);
				} else {
					newDescr = vulnGit.getDescription(); // overwriting, assuming Git descriptions are worded better!
				}
				vulnCna.setDescription(newDescr);// update description

				// merge sources from raw data
				for (String sUrl : vulnGit.getSourceURL())
					vulnCna.addSourceURL(sUrl);

				for (CompositeVulnerability vuln: cveHashMapScrapedFromCNAs.get(vulnCna.getCveId())) {
					for (String url: vuln.getSourceURL()) {
						if (!vulnCna.getSourceURL().contains(url)) {
							vulnCna.addSourceURL(url);
						}
					}
				}

				cveHashMapAll.put(cveId, vulnCna); // update existing CVE

			}
		}

		logger.info("***Merged CVEs! Out of {} Git CVEs, CVEs that exist only in Git (Not found at any available CNAs): {}, CVEs that are reserved in Git (But found at CNAs): {}",
				cveHashMapGithub.size(), cveCountFoundOnlyInGit, cveCountReservedInGit);
		return cveHashMapAll;
	}

	/**
	 * Identify New CVE and
	 * Process CVEs by comparing pulled CVEs to NVD and MITRE
	 * Calculate Time Gaps afterwards, if any
	 * @param cveHashMapAll
	 * @return
	 */
	public HashMap<String, List<Object>> processCVEs(HashMap<String, CompositeVulnerability> cveHashMapAll) {
		// process
		logger.info("Comparing CVES against NVD & MITRE..");
		String cveDataPathNvd = dataVars.get("dataDir") + "/nvd-cve.csv";
		String cveDataPathMitre = dataVars.get("dataDir") + "/mitre-cve.csv";
		CveProcessor cveProcessor = new CveProcessor(cveDataPathNvd, cveDataPathMitre);
		Map<String, Vulnerability> existingCves = databaseHelper.getExistingVulnerabilities();

		HashMap<String, List<Object>> checkedCVEs = cveProcessor.checkAgainstNvdMitre(cveHashMapAll, existingCves);

		return cveProcessor.checkTimeGaps(checkedCVEs, existingCves);
	}

	/**
	 * Reconcile for Characterization and DB processes
	 *
	 * @param cveListMap
	 * @return
	 */
	private List<CompositeVulnerability> reconcileCVEs(HashMap<String, List<Object>> cveListMap) {
		List<CompositeVulnerability> crawledVulnerabilityList = cveListMap.get("all").stream().map(e -> (CompositeVulnerability) e).collect(Collectors.toList());
		identifyNewOrUpdatedCve(crawledVulnerabilityList, databaseHelper);
		return crawledVulnerabilityList;
	}

	/**
	 * Identify updated CVEs in the crawled CVE list, to determine which ones to
	 * characterize. We do not want to characterize all crawled CVEs (that'd be toooo slow). The output of
	 * this method is used while storing CVEs into the DB as well. DatabaseHelper
	 * will update/insert new CVEs only!
	 *
	 *
	 * @param crawledVulnerabilityList list of all crawled CVEs from current run
	 * @param databaseHelper
	 * @return
	 */
	private List<CompositeVulnerability> identifyNewOrUpdatedCve(List<CompositeVulnerability> crawledVulnerabilityList, DatabaseHelper databaseHelper) {

		logger.info("Reconciling {} CVEs...", crawledVulnerabilityList.size());
		long startTime = System.currentTimeMillis();
		CveReconcilerFactory reconcileFactory = new CveReconcilerFactory();
		AbstractCveReconciler cveReconciler = reconcileFactory.createReconciler((String) dataVars.get("reconcilerMethod"));

		Map<String, Vulnerability> existingVulnMap = databaseHelper.getExistingVulnerabilities();

		int countUpdate = 0, countInsert = 0;
		for (int index = 0; index < crawledVulnerabilityList.size(); index++) {
			CompositeVulnerability vuln = crawledVulnerabilityList.get(index);

			// does CVE exist in the DB?
			if (existingVulnMap.containsKey(vuln.getCveId())) {
				Vulnerability existingAttribs = existingVulnMap.get(vuln.getCveId());
				String existingDescription = existingAttribs.getDescription(); // get existing description

				// do we need to update it?
				if (cveReconciler.reconcileDescriptions(existingDescription, vuln.getDescription(), null,
						vuln.getSourceDomainName(), false)) {
					countUpdate++;
					vuln.setCveReconcileStatus(CveReconcileStatus.UPDATE);
				} else {
					vuln.setCveReconcileStatus(CveReconcileStatus.DO_NOT_CHANGE); // no significant change
					continue;
				}

			} else {
				vuln.setCveReconcileStatus(CveReconcileStatus.INSERT); // does not exist, need to insert CVE
				countInsert++;
			}
			crawledVulnerabilityList.set(index, vuln); // update list
		}
		double minutes = (System.currentTimeMillis() - startTime) / 60.0 * 60 * 1000; // get elapsed minutes
		logger.info("Reconciling done! Identified {} new CVEs. {} and {} CVEs will be inserted and updated on the DB, respectively. Time{min} elapsed: {} ",
				(countInsert + countUpdate), countInsert, countUpdate, minutes);
		return crawledVulnerabilityList;
	}


	/**
	 * Use Characterizer Model to characterize CVEs and generate VDO/CVSS
	 * @param crawledVulnerabilityList
	 * @return
	 */
	private List<CompositeVulnerability> characterizeCVEs(List<CompositeVulnerability> crawledVulnerabilityList) {
		// Parse CAPECs page to link CVEs to a given Attack Pattern in characterizer
		// CapecParser capecParser = new CapecParser();
		// ArrayList<Capec> capecs = capecParser.parseWebPage(crawler);

		// characterize
		logger.info("Characterizing and scoring NEW CVEs...");

		String[] trainingDataInfo = properties.getCveCharacterizationTrainingDataInfo();
		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], properties.getCveCharacterizationApproach(),
				properties.getCveCharacterizationMethod(), false);

		return cveCharacterizer.characterizeCveList(crawledVulnerabilityList, databaseHelper,
				(Integer) characterizationVars.get("cveCharacterizationLimit"));
	}

	/**
	 * Store all processed CVEs in the DB
	 * @param crawledVulnerabilityList
	 * @param runId
	 */
	private void storeCVEs(List<CompositeVulnerability> crawledVulnerabilityList, int runId) {
		double dbTime;
		try {
			long databaseStoreStartTime = System.currentTimeMillis();
			logger.info("Storing crawled {} CVEs into the NVIP database with run id: {}", crawledVulnerabilityList.size(), runId);
			new DbParallelProcessor().executeInParallel(crawledVulnerabilityList, runId);
			dbTime = (System.currentTimeMillis() - databaseStoreStartTime) / 60000.0;
			NumberFormat formatter = new DecimalFormat("#0.00");
			logger.info("Spent {} minutes to store {} vulnerabilties.", formatter.format(dbTime), crawledVulnerabilityList.size());
		} catch (Exception e) {
			logger.error("Error occurred while storing CVEs: {}", e.toString());
		}

	}


	/**
	 * This method spawns a background process to identify affected product(s) for
	 * each scraped CVE.
	 *
	 * There are two options:
	 *
	 * (1) The affected product(s) that is/are already mapped to CPE item(s) could
	 * be already derived from the CVE publisher (by crawlers). The process will
	 * simply add the product(s) to the database.
	 *
	 *
	 * (2) The affected product name could be predicted by the previously trained
	 * product name extraction model (LSTM). In that case the predicted product name
	 * (string) should be mapped to a CPE item first. After that, it will be added
	 * to the database.
	 *
	 * // TODO We should be using more than 1 thread!!!!!!!!!!
	 *
	 * @param crawledVulnerabilityList
	 */
	private void spawnProcessToIdentifyAndStoreAffectedReleases(List<CompositeVulnerability> crawledVulnerabilityList) {
		AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(crawledVulnerabilityList);
		affectedProductIdentifier.start();
	}
}