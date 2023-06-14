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

import commits.PatchCommit;
import db.DatabaseHelper;
import model.CpeGroup;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.util.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main class for collecting CVE Patches within repos that were
 * previously collected from the PatchURLFinder class
 */
public class PatchFinder {
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());

	private static final ArrayList<PatchCommit> patchCommits = new ArrayList<>();
	protected static int cveLimit = 10;
	protected static int maxThreads = 10;
	protected static int cvesPerThread = 1;

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

	}

	public static void main(String[] args) throws IOException, InterruptedException {
		logger.info("Starting PatchFinder...");
		final long start = System.currentTimeMillis();

		// Load env vars
		fetchEnvVars();

		// Init db helper
		final DatabaseHelper databaseHelper = new DatabaseHelper();

		// Init PatchUrlFinder
		PatchUrlFinder patchURLFinder = new PatchUrlFinder();

		// Fetch affectedProducts from db
		Map<String, CpeGroup> affectedProducts = databaseHelper.getAffectedProducts();

		// Parse patch source urls from affectedProducts
		Map<String, ArrayList<String>> possiblePatchURLs = patchURLFinder.parseMassURLs(affectedProducts, cveLimit);

		// Find patches
		// Repos will be cloned to patch-repos directory, multi-threaded 6 threads.
		PatchFinder.findPatchesMultiThreaded(
				possiblePatchURLs,
				"nvip_data/patch-repos",
				maxThreads,
				cvesPerThread
		);

		// Get found patches from patchfinder
		ArrayList<PatchCommit> patchCommits = PatchFinder.getPatchCommits();

		// Insert patches
		for (PatchCommit patchCommit: patchCommits) {
			int vulnId = databaseHelper.getVulnIdByCveId(patchCommit.getCveId());
			databaseHelper.insertPatchSourceURL(vulnId, patchCommit.getCommitUrl());
			databaseHelper.insertPatchCommit(vulnId, patchCommit.getCommitUrl(), patchCommit.getCommitId(),
					patchCommit.getCommitDate(), patchCommit.getCommitMessage());
		}


		long delta = (System.currentTimeMillis() - start) / 1000;
		logger.info("Successfully patched {} affected products in {} seconds", patchCommits.size(), delta);
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
	 * @param clonePath
	 * @throws IOException
	 */
	public static void findPatchesMultiThreaded(Map<String, ArrayList<String>> possiblePatchSources, String clonePath,
														   int maxThreads, int limitCvePerThread) throws IOException {
		logger.info("Applying multi threading...");
		File dir = new File(clonePath);
		FileUtils.delete(dir, 1);

		logger.info(maxThreads + " available processors found");
		ArrayList<HashMap<String, ArrayList<String>>> sourceBatches = new ArrayList<>();

		// Initialize patchfinder threads
		for (int i=0; i < maxThreads; i++) {
			sourceBatches.add(new HashMap<>());
		}

		ExecutorService es = Executors.newFixedThreadPool(limitCvePerThread);
		// Divide cves equally amongst all threads, some threads may
		// have more sources based on their CVEs provided
		int numSourcesAdded = 1;
		int thread = 0;
		for (String cveId : possiblePatchSources.keySet()) {
			sourceBatches.get(thread).put(cveId, possiblePatchSources.get(cveId));
			numSourcesAdded++;
			if (numSourcesAdded % limitCvePerThread == 0 && thread < maxThreads - 1) {
				es.execute(new PatchFinderThread(sourceBatches.get(thread), clonePath));
				thread++;
			}
		}

		es.shutdown();
	}
}
