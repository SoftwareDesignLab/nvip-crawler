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
package edu.rit.se.nvip.patchfinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import edu.rit.se.nvip.patchfinder.commits.PatchCommit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.util.FileUtils;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.patchfinder.commits.PatchCommitScraper;

/**
 * Main class for collecting CVE Patches within repos that were
 * previously collected from the PatchURLFinder class
 *
 * TODO: Refactor to see if we need this, there should only be 1 parse method
 */
public final class PatchFinder {

	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());
	private static PatchCommitScraper previousRepo = null;
	private static final DatabaseHelper db = DatabaseHelper.getInstance();

	public static void main(String[] args) throws IOException {
		logger.info("Started Patches Application");

		PatchFinder main = new PatchFinder();
		//main.parse(args);

		logger.info("Patches Application Finished!");
	}

	/**
	 * Git commit parser that implements multiple threads to increase performance
	 * @param clonePath
	 * @throws IOException
	 */
	public ArrayList<PatchCommit> findPatchesMultiThreaded(Map<String, ArrayList<String>> possiblePatchSources, String clonePath, int breaker) throws IOException {
		logger.info("Applying multi threading...");
		File dir = new File(clonePath);
		FileUtils.delete(dir, 1);

		int maxThreads = Integer.parseInt(System.getenv("PATCHFINDER_MAX_THREADS"));

		logger.info(maxThreads + " available processors found");


		ArrayList<HashMap<String, ArrayList<String>>> sourceBatches = new ArrayList<>();

		// Initialize patchfinder threads
		for (int i=0; i < maxThreads; i++) {
			sourceBatches.add(new HashMap<>());
		}

		ExecutorService es = Executors.newFixedThreadPool(breaker);
		// Divide cves equally amongst all threads, some threads may
		// have more sources based on their CVEs provided
		int numSourcesAdded = 1;
		int thread = 0;
		for (String source : possiblePatchSources.keySet()) {
			sourceBatches.get(thread).put(source, possiblePatchSources.get(source));
			numSourcesAdded++;
			if (numSourcesAdded % breaker == 0 && thread < maxThreads - 1) {
				es.execute(new PatchFinderThread(sourceBatches.get(thread), clonePath, this));
				thread++;
			}
		}
		
		es.shutdown();
		return null;
	}


	/**
	 * Extract Method used for pulling commit data from a repo via source link and
	 * parsing commits for any commits related to CVEs
	 * 
	 * @param sourceURL
	 * @param clonePath
	 * @throws IOException
	 * @throws GitAPIException
	 */
	private void pullCommitData(String sourceURL, String clonePath, String cveId) {

		PatchCommitScraper parser = new PatchCommitScraper(sourceURL + ".git", clonePath);

		parser.cloneRepository();

		Map<java.util.Date, ArrayList<String>> commits = parser.parseCommits(cveId);

		if (commits.isEmpty()) {
			deletePatchSource(sourceURL);
		} else {
			for (java.util.Date commit : commits.keySet()) {
				insertPatchCommitData(sourceURL, commits.get(commit).get(0), commit, commits.get(commit).get(1));
			}
		}

		// Delete previously cloned local repo after storing
		// patch/commit data (to ensure the .pack file is closed in the .git directory)
		if (previousRepo != null) {
			previousRepo.deleteRepository();
		}
		previousRepo = parser;

	}

	/**
	 * Updates patch field by adding provided commit message and date that was
	 * pulled when parsing commits
	 * 
	 * @param commitDate
	 * @param commitMessage
	 */
	public void insertPatchCommitData(String sourceURL, String commitId, java.util.Date commitDate,
			String commitMessage) {

		logger.info("Inserting commit data to patchcommit table...");
		if (commitMessage.length() > 300) {
			commitMessage = commitMessage.substring(0, 299);
		}

		commitId = commitId.split(" ")[1];

		try {
			int id = db.getPatchSourceId(sourceURL);
			db.insertPatchCommit(id, sourceURL, commitId, commitDate, commitMessage);
			logger.info("Inserted commit from source ID: " + id);

		} catch (Exception e) {
			logger.error((e.getMessage()));
		}
	}

	/**
	 * Method used to delete Patch entries that lead to no commit data related to
	 * CVEs or patches
	 * 
	 * @param sourceURL
	 */
	public void deletePatchSource(String sourceURL) {
		logger.info("Deleting patch from database...");
		try {
			int id = db.getPatchSourceId(sourceURL);
			if (id != -1) {
				// Delete Patch Entry
				db.deleteCommits(id);

				// Delete Patch URL Entry
				db.deletePatchURL(id);
			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}


	/**
	 *
	 * @param file
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private List<String> processInputFile(File file) throws FileNotFoundException, IOException {
		ArrayList<String> repos = new ArrayList<>();

		BufferedReader br = new BufferedReader(new FileReader(file));
		String line;
		br.readLine(); // ignoring id in csv
		while ((line = br.readLine()) != null) {
			String[] entries = line.split(",");

			String repo = entries[0].trim();
			repos.add(repo.replace("https://api.", "https://").replace(".com/repos/", ".com/"));
		}
		return repos;
	}
}
