package patches; /**
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
import db.DatabaseHelper;
import env.PatchFinderEnvVars;
import model.CpeGroup;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;

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

//	private static final Set<PatchCommit> patchCommits = new HashSet<>();
	private static Map<String, List<String>> sourceDict;
	protected static Instant urlDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
	protected static final String[] addressBases = PatchFinderEnvVars.getAddressBases();
	protected static String clonePath = PatchFinderEnvVars.getClonePath();
	protected static String patchSrcUrlPath = PatchFinderEnvVars.getPatchSrcUrlPath();
	protected static int cveLimit = PatchFinderEnvVars.getCveLimit();
	protected static int maxThreads = PatchFinderEnvVars.getMaxThreads();
//	private static final BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>();

	public static DatabaseHelper getDatabaseHelper() { return databaseHelper; }

	/**
	 * Initialize the Patchfinder and its subcomponents
	 */
	public static void init(DatabaseHelper dbh) {
		logger.info("Initializing PatchFinder...");

		// Init db helper
		logger.info("Initializing DatabaseHelper...");
		databaseHelper = dbh;
	}

	/**
	 * Run a list of given jobs through the Patchfinder
	 * @param cveId CVE to get affected products and patches for
	 * @throws IOException if an IO error occurs while attempting to find patches
	 */
	public static void run(String cveId) throws IOException {
		// Get affected products via CVE ids
		final Map<String, CpeGroup> affectedProducts = databaseHelper.getAffectedProducts(cveId);
		final CpeGroup affectedProduct = affectedProducts.get(cveId);
		if(affectedProduct != null) {
			logger.info("Successfully got {} affected products for CVE '{}' from the database", affectedProduct.getVersionsCount(), cveId);
			PatchFinder.run(cveId, affectedProduct);
		} else logger.warn("No affected products found matching CVE '{}', cannot find patches.", cveId);
	}

	/**
	 * Find patches for a given map of affected products
	 * @param affectedProduct product to find patches for
	 * @throws IOException if an IO error occurs while attempting to find patches
	 *
	 * @return number of successfully imported patch commits
	 */
	public static int run(String cveId, CpeGroup affectedProduct) throws IOException {
		int successfulInserts = 0;

		// Attempt to find source urls from pre-written file (ensure file existence/freshness)
		final List<String> possiblePatchURLs = getDictUrls(cveId);
		final int readUrlCount = possiblePatchURLs.size();

		// Parse patch source urls from any affectedProducts that do not have fresh urls read from file
		logger.info("Parsing patch urls from affected product CVEs (limit: {} CVEs)...", cveLimit);
		final long parseUrlsStart = System.currentTimeMillis();

		// Determine if urls dict needs to be refreshed
		final boolean isStale = urlDictLastCompilationDate.until(Instant.now(), ChronoUnit.DAYS) >= 1;

		// Parse new urls
		final List<String> newUrls = PatchUrlFinder.parsePatchURLs(cveId, affectedProduct, cveLimit, isStale);
		possiblePatchURLs.addAll(newUrls);
		final int totalUrlCount = possiblePatchURLs.size();

		if(totalUrlCount > readUrlCount) {
			logger.info("Successfully parsed {} new possible patch urls for CVE '{}' in {} seconds",
					totalUrlCount - readUrlCount,
					cveId,
					(System.currentTimeMillis() - parseUrlsStart) / 1000
			);
			updateSourceDict(cveId, newUrls);
		} else if(totalUrlCount == 0) {
			logger.warn("No sources found for CVE '{}'", cveId);
			return successfulInserts;
		}


		// Find patches
		// Repos will be cloned to patch-repos directory, multi-threaded 6 threads.
		logger.info("Starting patch finder with {} max threads", maxThreads);
		final long findPatchesStart = System.currentTimeMillis();

		// Get found patches from patchfinder
		Set<PatchCommit> patchCommits = PatchFinder.findPatchesMultiThreaded(cveId, possiblePatchURLs);

		// Insert found patch commits (if any)
		if(patchCommits.size() > 0) {
			logger.info("Successfully found {} patch commits from {} patch urls in {} seconds",
					patchCommits.size(),
					possiblePatchURLs.size(),
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
						logger.warn("Failed to insert patch commit '{}' with message '{}' for CVE '{}', as it already exists in the database", commitSha.substring(0, 6), patchCommit.getCommitMessage(), cveId);
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

		return successfulInserts;
	}

	/**
	 * Search source dict for urls relating to given cve, always returns a valid List instance.
	 * @param cveId cve to search for
	 * @return found source urls
	 */
	public static List<String> getDictUrls(String cveId) {
		List<String> urls = new ArrayList<>();
		try {
			final List<String> tempUrls = getSourceDict().get(cveId);
			urls = tempUrls != null ? tempUrls : urls;
		} catch (IOException e) { logger.warn("Did not find any existing urls relating to CVE '{}'", cveId); }

		return urls;
	}

	/**
	 * Get the source dictionary safely (either load data on demand or get loaded data)
	 * @return acquired source dictionary
	 * @throws IOException if an error occurs while attempting to get the source dictionary
	 */
	private synchronized static Map<String, List<String>> getSourceDict() throws IOException {
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
	public static Map<String, List<String>> readSourceDict(String srcUrlPath) throws IOException {
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
		final LinkedHashMap<String, List<String>> sourceDict = (LinkedHashMap<String, List<String>>) rawData.get("urls");

		// Extract compilation time from file
		try {
			urlDictLastCompilationDate = Instant.parse((String) rawData.get("comptime"));
		} catch (DateTimeException e) {
			logger.error("Error parsing compilation date from dictionary: {}", e.toString());
		}

		// Log read in data stats
		int urlCount = sourceDict.values().stream().map(List::size).reduce(0, Integer::sum);
		if(urlCount > 0) {
			logger.info("Loaded {} possible patch urls for {} CVEs from file at filepath '{}'",
					urlCount,
					sourceDict.size(),
					patchSrcUrlPath
			);
		}

		// Return filled productDict
		return sourceDict;
	}

	/**
	 * Write the stored dictionary of urls to file at the stored dictionary path.
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	public static void writeSourceDict() {
		// Write data to file
		try {
			final Map<String, List<String>> sourceDict = PatchFinder.getSourceDict();
			// Build output data map
			final int urlCount = sourceDict.values().stream().map(List::size).reduce(0, Integer::sum);
			Map data = new LinkedHashMap<>();
			data.put("comptime", Instant.now().toString());
			data.put("urls", sourceDict);
			final ObjectWriter w = OM.writerWithDefaultPrettyPrinter();
			w.writeValue(new File(patchSrcUrlPath), data);
			logger.info("Successfully wrote {} source urls to source dict file at filepath '{}'", urlCount, patchSrcUrlPath);
		} catch (IOException e) {
			logger.error("Error writing product dict to filepath '{}': {}", patchSrcUrlPath, e.toString());
		}
	}

	/**
	 * Given a cveId and a list of newUrls, update the source dictionary with the new values.
	 *
	 * @param cveId cveId to update
	 * @param newUrls new urls to add
	 */
	private synchronized static void updateSourceDict(String cveId, List<String> newUrls) {
		try {
			// Get source dict
			final Map<String, List<String>> sourceDict = PatchFinder.getSourceDict();

			// Get existing urls
			List<String> urls = sourceDict.get(cveId);

			// Append new urls if existing urls found, else store only new urls
			if(urls != null) urls.addAll(newUrls);
			else urls = newUrls;

			// Put updated list of urls into dictionary
			sourceDict.put(cveId, urls);
		} catch (IOException e) {
			logger.error("Error updating product dict: {}", e.toString());
		}
	}

	/**
	 * Git commit parser that implements multiple threads to increase performance. Found patches
	 * will be stored in the patchCommits member of this class.
	 * @param possiblePatchSources sources to scrape
	 */
	public static Set<PatchCommit> findPatchesMultiThreaded(String cveId, List<String> possiblePatchSources) {
		final Set<PatchCommit> patchCommits = new HashSet<>();
		// TODO: Move to where the logic actually clones, so this is not called unnecessarily
		// Init clone path and clear previously stored repos
		File dir = new File(clonePath);
		if(!dir.exists()) {
			logger.warn("Could not locate clone directory at path '{}'", clonePath);
			try { dir.createNewFile(); }
			catch (IOException e) { logger.error("Failed to create missing directory '{}'", clonePath); }
		}

		final int actualThreads = possiblePatchSources.size();

		// TODO: Implement futures
		final List<Future<Set<PatchCommit>>> futures = new ArrayList<>();
		final ExecutorService exe = Executors.newFixedThreadPool(actualThreads);

		// Partition jobs to all threads
		for (String source : possiblePatchSources) {
			Future<Set<PatchCommit>> future = exe.submit(() -> {
				// Create thread, run, and get found patch commits after run has completed
				final PatchFinderThread thread = new PatchFinderThread(cveId, source, clonePath, 10000);
				thread.run();
				return thread.getPatchCommits();
			});
			futures.add(future);
		}

		// Initiate shutdown of executor (waits, but does not hang, for all jobs to complete)
		exe.shutdown();

		for (Future<Set<PatchCommit>> future : futures) {
			try {
				final Set<PatchCommit> result = future.get();
				if(result != null) patchCommits.addAll(result);
			} catch (Exception e) { logger.error("Error occured while getting future of job: {}", e.toString()); }
		}

		logger.info("Returning {} patch commits", patchCommits.size());
		return patchCommits;
	}
}
