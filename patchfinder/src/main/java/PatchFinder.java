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
import java.util.stream.Collectors;

/**
 * Main class for collecting CVE Patches within repos that were
 * previously collected from the PatchURLFinder class
 *
 * @author Dylan Mulligan
 */
public class PatchFinder {
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());

	private static final ObjectMapper OM = new ObjectMapper();
	private static DatabaseHelper databaseHelper;
	private static PatchUrlFinder patchURLFinder;

	private static final ArrayList<PatchCommit> patchCommits = new ArrayList<>();
	private static Map<String, ArrayList<String>> sourceDict;
	protected static Instant urlDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
	protected static final String[] addressBases = PatchFinderEnvVars.getAddressBases();
	protected static String clonePath = PatchFinderEnvVars.getClonePath();
	protected static String patchSrcUrlPath = PatchFinderEnvVars.getPatchSrcUrlPath();
	protected static int cveLimit = PatchFinderEnvVars.getCveLimit();
	protected static int maxThreads = PatchFinderEnvVars.getMaxThreads();

	public static DatabaseHelper getDatabaseHelper() { return databaseHelper; }

	/**
	 * Initialize the Patchfinder and its subcomponents
	 */
	public static void init() {
		logger.info("Initializing PatchFinder...");

		// Init db helper
		logger.info("Initializing DatabaseHelper...");
		databaseHelper = new DatabaseHelper(
				PatchFinderEnvVars.getDatabaseType(),
				PatchFinderEnvVars.getHikariUrl(),
				PatchFinderEnvVars.getHikariUser(),
				PatchFinderEnvVars.getHikariPassword()
		);

		// Init PatchUrlFinder
		logger.info("Initializing PatchUrlFinder...");
		patchURLFinder = new PatchUrlFinder();
	}

	/**
	 * Run a list of given jobs through the Patchfinder
	 * @param cveIds CVEs to get affected products and patches for
	 * @throws IOException if an IO error occurs while attempting to find patches
	 * @throws InterruptedException if a thread interrupted error occurs while attempting to find patches
	 */
	public static void run(List<String> cveIds) throws IOException, InterruptedException {
		// Get affected products via CVE ids
		final Map<String, CpeGroup> affectedProducts = databaseHelper.getAffectedProducts(cveIds);
		logger.info("Successfully got affected products for {} CVEs from the database", affectedProducts.size());
		PatchFinder.run(affectedProducts, 0);
	}

	/**
	 * Find patches for a given map of affected products
	 * @param affectedProducts map of products to find patches for
	 * @throws IOException if an IO error occurs while attempting to find patches
	 *
	 * @return number of successfully imported patch commits
	 */
	public static int run(Map<String, CpeGroup> affectedProducts, int cveLimit) throws IOException {
		final long totalStart = System.currentTimeMillis();
		int successfulInserts = 0;

		// Attempt to find source urls from pre-written file (ensure file existence/freshness)
		final Map<String, ArrayList<String>> possiblePatchURLs = getSourceDict();

		// Filter any sources that are not a current job
		final Set<String> cachedCVEs = possiblePatchURLs.keySet();
		final Set<String> newCVEs = new HashSet<>(affectedProducts.keySet()); // Prevents concurrent mod exceptions
		List<String> keysToRemove = new ArrayList<>();
		for (String key : cachedCVEs) {
			if (!newCVEs.contains(key)) {
				keysToRemove.add(key);
			}
		}

		// Remove keys outside the loop
		for (String keyToRemove : keysToRemove) {
			possiblePatchURLs.remove(keyToRemove);
		}

		// Log read in data stats
		int urlCount = possiblePatchURLs.values().stream().map(ArrayList::size).reduce(0, Integer::sum);
		if(urlCount > 0) {
			logger.info("Loaded {} possible patch urls for {} CVEs from file at filepath '{}'",
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

		// Parse new urls
		patchURLFinder.parsePatchURLs(possiblePatchURLs, affectedProducts, cveLimit, isStale);
		urlCount = possiblePatchURLs.values().stream().map(ArrayList::size).reduce(0, Integer::sum);

		if(urlCount > 0) {
			logger.info("Successfully parsed {} possible patch urls for {} CVE(s) in {} seconds",
					urlCount,
					possiblePatchURLs.size(),
					(System.currentTimeMillis() - parseUrlsStart) / 1000
			);
		} else {
			logger.warn("No sources found for {} CVE(s)", possiblePatchURLs.size());
			return successfulInserts;
		}


		// Write found source urls to file
		writeSourceDict(patchSrcUrlPath, possiblePatchURLs);

		// Find patches
		// Repos will be cloned to patch-repos directory, multi-threaded 6 threads.
		logger.info("Starting patch finder with {} max threads", maxThreads);
		final long findPatchesStart = System.currentTimeMillis();
		PatchFinder.findPatchesMultiThreaded(possiblePatchURLs);

		// Get found patches from patchfinder
		ArrayList<PatchCommit> patchCommits = PatchFinder.getPatchCommits();

		// Insert found patch commits (if any)
		if(patchCommits.size() > 0) {
			logger.info("Successfully found {} patch commits from {} patch urls in {} seconds",
					patchCommits.size(),
					urlCount,
					(System.currentTimeMillis() - findPatchesStart) / 1000
			);

			// Get existing sources
			final Map<String, Integer> existingSources = databaseHelper.getExistingSourceUrls();

			// Get existing patch commits
			final Set<String> existingCommitShas = databaseHelper.getExistingPatchCommitShas();

			// Insert patches
			int failedInserts = 0;
			int existingInserts = 0;
			logger.info("Starting insertion of {} patch commits into the database...", patchCommits.size());
			final long insertPatchesStart = System.currentTimeMillis();
			for (PatchCommit patchCommit : patchCommits) {
				final String sourceUrl = patchCommit.getCommitUrl();
				// Insert source
				final int sourceUrlId = databaseHelper.insertPatchSourceURL(existingSources, patchCommit.getCveId(), sourceUrl);
				//convert the timeline to a string

				// Insert patch commit
				try {
					// Ensure patch commit does not already exist
					final String commitSha = patchCommit.getCommitId();
					if (!existingCommitShas.contains(commitSha)) {
						databaseHelper.insertPatchCommit(
								sourceUrlId, patchCommit.getCveId(), commitSha, patchCommit.getCommitDate(),
								patchCommit.getCommitMessage(), patchCommit.getUniDiff(),
								patchCommit.getTimeline(), patchCommit.getTimeToPatch(), patchCommit.getLinesChanged()
						);
					} else {
						logger.warn("Failed to insert patch commit, as it already exists in the database");
						existingInserts++;
					}
				} catch (IllegalArgumentException e) {
					failedInserts++;
				}
			}

			successfulInserts = patchCommits.size() - failedInserts - existingInserts;

			logger.info("Successfully inserted {} patch commits into the database in {} seconds ({} failed {} already existed)",
					successfulInserts,
					(System.currentTimeMillis() - insertPatchesStart) / 1000,
					failedInserts,
					existingInserts
			);
		} else logger.info("No patch commits found"); // Otherwise log failure to find patch



		final long delta = (System.currentTimeMillis() - totalStart) / 1000;
		logger.info("Successfully collected {} patch commits from {} CVEs in {} seconds",
				patchCommits.size(),
				Math.min(cveLimit, affectedProducts.size()),
				delta
		);

		return successfulInserts;
	}

	/**
	 * Get the source dictionary safely (either load data on demand or get loaded data)
	 * @return acquired source dictionary
	 * @throws IOException if an error occurs while attempting to get the source dictionary
	 */
	private static Map<String, ArrayList<String>> getSourceDict() throws IOException {
		// Ensure source dict is loaded
		if(sourceDict == null) sourceDict = readSourceDict(patchSrcUrlPath);

		// Return source dict
		return sourceDict;
	}

	/**
	 * Reads a source dictionary JSON file at the given path and return the mapped results.
	 * @param srcUrlPath path to source dictionary
	 * @return found source map
	 * @throws IOException if an error occurs while attempting to read the source dictionary
	 */
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

	/**
	 * Write the given dictionary of urls to file at the given path.
	 * @param patchSrcUrlPath path to write to
	 * @param urls dictionary to write
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	private static void writeSourceDict(String patchSrcUrlPath, Map<String, ArrayList<String>> urls) {
		final int urlCount = urls.values().stream().map(ArrayList::size).reduce(0, Integer::sum);
		// Build output data map
		Map data = new LinkedHashMap<>();
		data.put("comptime", Instant.now().toString());
		data.put("urls", urls);

		// Write data to file
		try {
			final ObjectWriter w = OM.writerWithDefaultPrettyPrinter();
			w.writeValue(new File(patchSrcUrlPath), data);
			logger.info("Successfully wrote {} source urls to source dict file at filepath '{}'", urlCount, patchSrcUrlPath);
		} catch (IOException e) {
			logger.error("Error writing product dict to filepath '{}': {}", patchSrcUrlPath, e.toString());
		}
	}

	public static ArrayList<PatchCommit> getPatchCommits() {
		return patchCommits;
	}

	/**
	 * Git commit parser that implements multiple threads to increase performance. Found patches
	 * will be stored in the patchCommits member of this class.
	 * @param possiblePatchSources sources to scrape
	 */
	public static void findPatchesMultiThreaded(Map<String, ArrayList<String>> possiblePatchSources) {
		// Init clone path and clear previously stored repos
		File dir = new File(clonePath);
		if(!dir.exists()) {
			logger.warn("Unable to locate clone path '{}' for previous run repo deletion", clonePath);
			try { dir.createNewFile(); }
			catch (IOException e) { logger.error("Failed to create missing directory '{}'", clonePath); }
		}
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

		// Initialize thread pool executor
		final int actualThreads = Math.min(maxThreads, totalCVEsToProcess);
		final BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(totalPatchSources.get());
		final ThreadPoolExecutor executor = new ThreadPoolExecutor(
				actualThreads,
				actualThreads,
				5,
				TimeUnit.MINUTES,
				workQueue
		);

		// Prestart all assigned threads (this is what runs jobs)
		executor.prestartAllCoreThreads();

		// Add jobs to work queue (ignore CVEs with no found sources
		final Set<String> CVEsToProcess = possiblePatchSources.keySet()
				.stream().filter(
						k -> possiblePatchSources.get(k).size() > 0).collect(Collectors.toSet()
				);

		// Partition jobs to all threads
		int i = 0;
		for (String cveId : CVEsToProcess) {
			if(i >= cveLimit) {
				logger.info("Hit defined CVE_LIMIT of {}, skipping {} remaining CVEs...", cveLimit, CVEsToProcess.size() - cveLimit);
				break;
			}

			final HashMap<String, ArrayList<String>> sourceBatch = new HashMap<>();
			sourceBatch.put(cveId, possiblePatchSources.get(cveId));
			if(!workQueue.offer(new PatchFinderThread(sourceBatch, clonePath, 10000))) {
				logger.error("Could not add job '{}' to work queue", cveId);
			}
			i++;
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
					final int activeJobs = executor.getActiveCount();
					final int currNumCVEs = workQueue.size() + activeJobs; // Current number of remaining CVEs
					final int deltaNumCVEs = lastNumCVEs - currNumCVEs; // Change in CVEs since last progress update

					// Sum number processed
					numCVEsProcessed += deltaNumCVEs;

					// Calculate rate, avg rate, and remaining time
					final double avgRate = (double) numCVEsProcessed / ((double) secondsWaiting / 60); // CVEs/sec
					final double remainingAvgTime = currNumCVEs / avgRate; // CVEs / CVEs/min = remaining mins

					// Log stats
					logger.info(
							"{} out of {} CVEs done (SP: {} CVEs/min | AVG SP: {} CVEs/min | Est time remaining: {} minutes ({} seconds) | {} active jobs)...",
							totalCVEsToProcess - currNumCVEs,
							totalCVEsToProcess,
							Math.floor((double) deltaNumCVEs * 100) / 100,
							Math.floor(avgRate * 100) / 100,
							Math.floor(remainingAvgTime * 100) / 100,
							Math.floor(remainingAvgTime * 60 * 100) / 100,
							activeJobs
					);

					// Update lastNumCVEs
					lastNumCVEs = currNumCVEs;
				}
			}
		} catch (Exception e) {
			logger.error("Patch finding failed: {}", e.toString());
			List<Runnable> remainingTasks = executor.shutdownNow();
			logger.error("{} tasks not executed", remainingTasks.size());
		}
	}
}
