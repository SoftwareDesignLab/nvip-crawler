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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import commits.PatchCommit;
import db.DatabaseHelper;
import model.CpeGroup;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.util.FileUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Main class for collecting CVE Patches within repos that were
 * previously collected from the PatchURLFinder class
 *
 * @author Dylan Mulligan
 */
public class PatchFinder {
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());

	private static final ArrayList<PatchCommit> patchCommits = new ArrayList<>();
	protected static int cveLimit = 20;
	protected static int maxThreads = 10;
	protected static int cvesPerThread = 1;
	protected static String databaseType = "mysql";
	protected static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
	protected static String hikariUser = "root";
	protected static String hikariPassword = "root";
	protected static int cloneCommitThreshold = 1000; // TODO: Find omptimal value once github scraping is working well
	protected static int cloneCommitLimit = 50000; // TODO: Find omptimal value once github scraping is working well
	protected static String clonePath = "patchfinder/src/main/resources/patch-repos";
	protected static String patchSrcUrlPath = "patchfinder/src/main/resources/source_dict.json";
	protected static String[] addressBases = { "https://github.com/", "https://www.gitlab.com/" };
	protected static Instant urlDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
	private static final ObjectMapper OM = new ObjectMapper();

	public static int getCloneCommitThreshold() { return cloneCommitThreshold; }
	public static int getCloneCommitLimit() { return cloneCommitLimit; }

	/**
	 * Attempts to get all required environment variables from System.getenv() safely, logging
	 * any missing or incorrect variables.
	 */
	protected static void fetchEnvVars() {
		// Fetch ENV_VARS and set all found configurable properties
		final Map<String, String> props = System.getenv();

		try {
			if(props.containsKey("CVE_LIMIT")) {
				cveLimit = Integer.parseInt(System.getenv("CVE_LIMIT"));
				logger.info("Setting CVE_LIMIT to {}", cveLimit);
			} else throw new Exception();
		} catch (Exception ignored) { logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to {}", cveLimit); }

		try{
			if(props.containsKey("ADDRESS_BASES")) {
				addressBases = System.getenv("ADDRESS_BASES").split(",");
				logger.info("Setting ADDRESS_BASES to {}", Arrays.toString(addressBases));
			} else throw new Exception();
		}catch(Exception ignored) {logger.warn("Could not fetch ADDRESS_BASES from env vars, defaulting to {}", Arrays.toString(addressBases)); }

		try {
			if(props.containsKey("MAX_THREADS")) {
				maxThreads = Integer.parseInt(System.getenv("MAX_THREADS"));
				logger.info("Setting MAX_THREADS to {}", maxThreads);
			} else throw new Exception();
		}catch (Exception ignored) { logger.warn("Could not fetch MAX_THREADS from env vars, defaulting to {}", maxThreads); }

		try{
			if(props.containsKey("CVES_PER_THREAD")) {
				cvesPerThread = Integer.parseInt(System.getenv("CVES_PER_THREAD"));
				logger.info("Setting CVES_PER_THREAD to {}", cvesPerThread);
			} else throw new Exception();
		}catch(Exception ignored) {logger.warn("Could not fetch CVES_PER_THREAD from env vars, defaulting to {}", cvesPerThread); }

		try{
			if(props.containsKey("CLONE_PATH")) {
				clonePath = System.getenv("CLONE_PATH");
				logger.info("Setting CLONE_PATH to {}", clonePath);
			} else throw new Exception();
		}catch(Exception ignored) {logger.warn("Could not fetch CLONE_PATH from env vars, defaulting to {}", clonePath); }

		try{
			if(props.containsKey("DB_TYPE")) {
				databaseType = System.getenv("DB_TYPE");
				logger.info("Setting DB_TYPE to {}", databaseType);
			} else throw new Exception();
		}catch(Exception ignored) {logger.warn("Could not fetch DB_TYPE from env vars, defaulting to {}", databaseType); }

		try{
			if(props.containsKey("CLONE_COMMIT_THRESHOLD")) {
				cloneCommitThreshold = Integer.parseInt(System.getenv("CLONE_COMMIT_THRESHOLD"));
				logger.info("Setting CLONE_COMMIT_THRESHOLD to {}", cloneCommitThreshold);
			} else throw new Exception();
		}catch(Exception ignored) {logger.warn("Could not fetch CLONE_COMMIT_THRESHOLD from env vars, defaulting to {}", cloneCommitThreshold); }

		fetchHikariEnvVars(props);
	}

	private static void fetchHikariEnvVars(Map<String, String> props) {
		try {
			if(props.containsKey("HIKARI_URL")) {
				hikariUrl = System.getenv("HIKARI_URL");
				logger.info("Setting HIKARI_URL to {}", hikariUrl);
			} else throw new Exception();
		} catch (Exception ignored) { logger.warn("Could not fetch HIKARI_URL from env vars, defaulting to {}", hikariUrl); }

		try {
			if(props.containsKey("HIKARI_USER")) {
				hikariUser = System.getenv("HIKARI_USER");
				logger.info("Setting HIKARI_USER to {}", hikariUser);
			} else throw new Exception();
		} catch (Exception ignored) { logger.warn("Could not fetch HIKARI_USER from env vars, defaulting to {}", hikariUser); }

		try {
			if(props.containsKey("HIKARI_PASSWORD")) {
				hikariPassword = System.getenv("HIKARI_PASSWORD");
				logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
			} else throw new Exception();
		} catch (Exception ignored) { logger.warn("Could not fetch HIKARI_PASSWORD from env vars, defaulting to {}", hikariPassword); }
	}

	public static void main(String[] args) throws IOException, InterruptedException {
		logger.info("Starting PatchFinder...");
		final long totalStart = System.currentTimeMillis();

		// Load env vars
		logger.info("Fetching needed environment variables...");
		fetchEnvVars();
		logger.info("Done fetching environment variables");

		// Init db helper
		logger.info("Initializing DatabaseHelper and getting affected products from the database...");
		final DatabaseHelper databaseHelper = new DatabaseHelper(databaseType, hikariUrl, hikariUser, hikariPassword);

		// Init PatchUrlFinder
		PatchUrlFinder patchURLFinder = new PatchUrlFinder();

		// Fetch affectedProducts from db
		Map<String, CpeGroup> affectedProducts = databaseHelper.getAffectedProducts();
		final int affectedProductsCount = affectedProducts.values().stream().map(CpeGroup::getVersionsCount).reduce(0, Integer::sum);
		logger.info("Successfully got {} CVEs mapped to {} affected products from the database", affectedProducts.size(), affectedProductsCount);

		// Attempt to find source urls from pre-written file (ensure file existence/freshness)
		final Map<String, ArrayList<String>> possiblePatchURLs = readSourceDict(patchSrcUrlPath);

		// Log read in data stats
		int urlCount = possiblePatchURLs.values().stream().map(ArrayList::size).reduce(0, Integer::sum);
		if(urlCount > 0) {
			logger.info("Successfully read {} possible patch urls for {} CVEs from file at filepath '{}'",
					urlCount,
					possiblePatchURLs.size(),
					patchSrcUrlPath
			);
		}

		// Parse patch source urls from any affectedProducts that do not have fresh urls read from file
		logger.info("Parsing patch urls from affected product CVEs (limit: {} CVEs)...", cveLimit);
		final long parseUrlsStart = System.currentTimeMillis();

		// Determine if urls dict needs to be refreshed
		final boolean isStale = urlDictLastCompilationDate.until(Instant.now(), ChronoUnit.DAYS) >= 1;
		// TODO: Add offset to avoid repeating the same run?
		// Parse new urls
		patchURLFinder.parseMassURLs(possiblePatchURLs, affectedProducts, cveLimit, isStale);
		urlCount = possiblePatchURLs.values().stream().map(ArrayList::size).reduce(0, Integer::sum);

		logger.info("Successfully parsed {} possible patch urls for {} CVEs in {} seconds",
				urlCount,
				possiblePatchURLs.size(),
				(System.currentTimeMillis() - parseUrlsStart) / 1000
		);

		// Write found source urls to file
		writeSourceDict(patchSrcUrlPath, possiblePatchURLs);

		// Find patches
		// Repos will be cloned to patch-repos directory, multi-threaded 6 threads.
		// TODO: Fix cvesPerThread
		logger.info("Starting patch finder with {} max threads, allowing {} CVE(s) per thread...", maxThreads, cvesPerThread);
		final long findPatchesStart = System.currentTimeMillis();
		//TODO: How to handle multiple CVEs mapped to the same repo.
		// Currently we clone/scrape for each, which is a big waste of time
		PatchFinder.findPatchesMultiThreaded(possiblePatchURLs);

		// Get found patches from patchfinder
		ArrayList<PatchCommit> patchCommits = PatchFinder.getPatchCommits();
		logger.info("Successfully found {} patch commits from {} patch urls in {} seconds",
				patchCommits.size(),
				urlCount,
				(System.currentTimeMillis() - findPatchesStart) / 1000
		);

		//TODO: Ensure patch commit does not already exist before inserting.
		// For existing entries, diff, replace, ignore?

		// Get existing sources
		final Map<String, Integer> existingSources = databaseHelper.getExistingSourceUrls();

		// Get existing patch commits
		final Set<String> existingCommitUrls = databaseHelper.getExistingPatchCommitUrls();

		// Insert patches
		int failedInserts = 0;
		int existingInserts = 0;
		logger.info("Starting insertion of {} patch commits into the database...", patchCommits.size());
		final long insertPatchesStart = System.currentTimeMillis();
		for (PatchCommit patchCommit : patchCommits) {
			final String sourceUrl = patchCommit.getCommitUrl();
			// Insert source
			final int sourceUrlId = databaseHelper.insertPatchSourceURL(existingSources, patchCommit.getCveId(), sourceUrl);

			// Insert patch commit
			try {
				// Ensure patch commit does not already exist
				final String commitUrl = patchCommit.getCommitUrl() + "/commit/" + patchCommit.getCommitId();
				if(!existingCommitUrls.contains(commitUrl)) {
					databaseHelper.insertPatchCommit(
							sourceUrlId, commitUrl, patchCommit.getCommitDate(),
							patchCommit.getCommitMessage(), patchCommit.getUniDiff(),
							patchCommit.getTimeline(), patchCommit.getTimeToPatch(), patchCommit.getLinesChanged()
					);
				} else {
//					logger.warn("Failed to insert patch commit, as it was already found in the db");
					existingInserts++;
				}
			} catch (IllegalArgumentException e) {
				failedInserts++;
			}
		}

		logger.info("Successfully inserted {} patch commits into the database in {} seconds ({} failed {} already existed)",
				patchCommits.size() - failedInserts - existingInserts,
				(System.currentTimeMillis() - insertPatchesStart) / 1000,
				failedInserts,
				existingInserts
		);

		final long delta = (System.currentTimeMillis() - totalStart) / 1000;
		logger.info("Successfully collected {} patch commits from {} CVEs in {} seconds",
				patchCommits.size(),
				Math.min(cveLimit, affectedProducts.size()),
				delta
		);
	}

	@SuppressWarnings({"unchecked"})
	public static Map<String, ArrayList<String>> readSourceDict(String srcUrlPath) throws IOException {
		// Read in raw data, and return an empty hashmap if this fails for any reason
		final LinkedHashMap<String, ?> rawData;
		try {
			rawData = OM.readValue(Paths.get(srcUrlPath).toFile(), LinkedHashMap.class);
		} catch (FileNotFoundException e) {
			logger.info("Could not find patch source dictionary at filepath '{}'", srcUrlPath);
			return new HashMap<>();
		} catch (JsonParseException e) {
			logger.info("Failed to parse patch source dictionary at filepath '{}': {}", srcUrlPath, e.toString());
			return new HashMap<>();
		}

		// Extract source url map
		final LinkedHashMap<String, ArrayList<String>> sourceDict = (LinkedHashMap<String, ArrayList<String>>) rawData.get("urls");

		// Extract compilation time from file
		try {
			urlDictLastCompilationDate = Instant.parse((String) rawData.get("comptime"));
		} catch (DateTimeException e) {
			logger.error("Error parsing compilation date from dictionary: {}", e.toString());
		}

		// Return filled productDict
		return sourceDict;
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	private static void writeSourceDict(String patchSrcUrlPath, Map<String, ArrayList<String>> urls) {
		// Build output data map
		Map data = new LinkedHashMap<>();
		data.put("comptime", Instant.now().toString());
		data.put("urls", urls);

		// Write data to file
		try {
			final ObjectWriter w = OM.writerWithDefaultPrettyPrinter();
			w.writeValue(new File(patchSrcUrlPath), data);
			logger.info("Successfully wrote {} source urls to source dict file at filepath '{}'", urls.size(), patchSrcUrlPath);
		} catch (IOException e) {
			logger.error("Error writing product dict to filepath '{}': {}", patchSrcUrlPath, e.toString());
		}
	}

	/**
	 * Getter for patch commits list
	 * Used byb threads to add more entries
	 * @return
	 */
	public static ArrayList<PatchCommit> getPatchCommits() {
		return patchCommits;
	}

	/**
	 * Git commit parser that implements multiple threads to increase performance
	 * @param possiblePatchSources
	 * @throws IOException
	 */
	public static void findPatchesMultiThreaded(Map<String, ArrayList<String>> possiblePatchSources) throws IOException {
		// Init clone path and clear previously stored repos
		File dir = new File(clonePath);
		if(!dir.exists()) logger.warn("Unable to locate clone path for previous run repo deletion");
		else {
			logger.info("Clearing any existing repos @ '{}'", clonePath);
			try { FileUtils.delete(dir, FileUtils.RECURSIVE); }
			catch (IOException e) { logger.error("Failed to clear clone dir @ '{}': {}", dir, e); }
		}

		// Determine the actual number of CVEs to be processed
		final int totalCVEsToProcess = Math.min(possiblePatchSources.size(), cveLimit);

		// Determine the total number of possible patch sources to scrape
		final AtomicInteger totalPatchSources = new AtomicInteger();
		possiblePatchSources.values().stream().map(ArrayList::size).forEach(totalPatchSources::addAndGet);

		// If there are less CVEs to process than maxThreads, only create cveLimit number of threads
		if(totalCVEsToProcess < maxThreads){
			logger.info("Number of CVEs to process {} is less than available threads {}, setting number of available threads to {}", cveLimit, maxThreads, cveLimit);
			maxThreads = totalCVEsToProcess;
		}

		// Initialize data structures
		ArrayList<HashMap<String, ArrayList<String>>> sourceBatches = new ArrayList<>();
		final BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(totalPatchSources.get());
		final ThreadPoolExecutor executor = new ThreadPoolExecutor(
				maxThreads,
				maxThreads,
				5,
				TimeUnit.MINUTES,
				workQueue
		);

		// Prepare source batches for jobs
		for (int i=0; i < maxThreads; i++) {
			sourceBatches.add(new HashMap<>());
		}

		// Prestart all assigned threads (this is what runs jobs)
		executor.prestartAllCoreThreads();

		// Add jobs to work queue
		final Set<String> CVEsToProcess = possiblePatchSources.keySet();

		// Find # of CVEs per thread (ignoring remainder)
		final int CVEsPerThread = (int) Math.floor((double) CVEsToProcess.size() / maxThreads);

		// Partition jobs to all threads
		int i = 0;
		int thread = 0;
		for (String cveId : CVEsToProcess) {
			if(i >= cveLimit) {
				logger.info("Hit defined CVE_LIMIT of {}, skipping {} remaining CVEs...", cveLimit, CVEsToProcess.size() - cveLimit);
				break;
			}

//			sourceBatches.get(thread).put(cveId, possiblePatchSources.get(cveId));
			final HashMap<String, ArrayList<String>> sourceBatch = new HashMap<>();
			sourceBatch.put(cveId, possiblePatchSources.get(cveId));
			if(!workQueue.offer(new PatchFinderThread(sourceBatch, clonePath, 10000))) {
				logger.error("Could not add job '{}' to work queue", cveId);
			}
			i++;

			// Iterate thread counter only once per partition
			if(i % CVEsPerThread == 0) thread++; // TODO: Remainder?
		}

		// Initiate shutdown of executor (waits, but does not hang, for all jobs to complete)
		executor.shutdown();

		// Wait loop (waits for jobs to be processed and updates the user on progress)
		final int timeout = 15;
		long secondsWaiting = 0;
		int numCVEsProcessed = 0;
		int lastNumCVEs = totalCVEsToProcess;
		try {
			while(!executor.awaitTermination(timeout, TimeUnit.SECONDS)) {
				secondsWaiting += timeout;

				// Every minute, log a progress update
				if(secondsWaiting % 60 == 0) {

					// Determine number of CVEs processed
					final int currNumCVEs = workQueue.size() + executor.getActiveCount(); // Current number of remaining CVEs
					final int deltaNumCVEs = lastNumCVEs - currNumCVEs; // Change in CVEs since last progress update

					// Sum number processed
					numCVEsProcessed += deltaNumCVEs;

					// Calculate rate, avg rate, and remaining time
					final double rate = (double) deltaNumCVEs; // CVEs/min
					final double avgRate = (double) numCVEsProcessed / ((double) secondsWaiting / 60); // CVEs/sec
					final double remainingAvgTime = currNumCVEs / rate; // CVEs / CVEs/min = remaining mins

					// Log stats
					logger.info(
							"{} out of {} CVEs processed (SP: {} CVEs/min | AVG SP: {} CVEs/min | Est time remaining: {} minutes ({} seconds))...",
							totalCVEsToProcess - currNumCVEs,
							totalCVEsToProcess,
							Math.floor(rate * 100) / 100,
							Math.floor(avgRate * 100) / 100,
							Math.floor(remainingAvgTime * 100) / 100,
							Math.floor(remainingAvgTime * 60 * 100) / 100
					);

					// Update lastNumCVEs
					lastNumCVEs = currNumCVEs;
				}

//				 Timeout for whole process
//				if((secondsWaiting / 60) > 5) throw new TimeoutException("Timeout reached before all threads completed");
			}
		} catch (Exception e) {
			logger.error("Patch finding failed: {}", e.toString());
			List<Runnable> remainingTasks = executor.shutdownNow();
			logger.error("{} tasks not executed", remainingTasks.size());
		}
	}
}
