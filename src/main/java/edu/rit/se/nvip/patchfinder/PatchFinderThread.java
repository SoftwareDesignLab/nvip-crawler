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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.patchfinder.commits.PatchCommitScraper;
import edu.rit.se.nvip.utils.GitController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Runnable thread class for multithreaded patch finder
 */
public class PatchFinderThread implements Runnable {
	private final HashMap<String, ArrayList<String>> cvePatchEntry;
	private final String clonePath;
	private static final Logger logger = LogManager.getLogger(PatchFinder.class.getName());
	private PatchCommitScraper previous;
	private static final DatabaseHelper db = DatabaseHelper.getInstance();
	private final PatchFinder patchDownloader;

	/**
	 * Thread object used for multithreaded patchfinding
	 * @param sources
	 * @param clonePath
	 * @param patchDownloader
	 */
	public PatchFinderThread(HashMap<String, ArrayList<String>> sources, String clonePath, PatchFinder patchDownloader) {
		this.cvePatchEntry = sources;
		this.clonePath = clonePath;
		this.patchDownloader = patchDownloader;
	}

	/**
	 * Used for cloning, crawling, and deleting product repos to find patch commits
	 */
	@Override
	public void run() {
		for (String cve : cvePatchEntry.keySet()) {
			for (String patchSource: cvePatchEntry.get(cve)) {
				try {
					GitController gitController = new GitController(clonePath, patchSource+".git");
					gitController.cloneRepo();
					Map<Date, ArrayList<String>> commits = repo.parseCommits(cve);
					if (commits.isEmpty()) {
						patchDownloader.deletePatchSource(source.getValue());
					} else {
						for (java.util.Date commit : commits.keySet()) {
							patchDownloader.insertPatchCommitData(source.getValue(), commits.get(commit).get(0), commit, commits.get(commit).get(1));
						}
					}

					if (previous != null) {
						previous.deleteRepository();
					}

					previous = repo;

				} catch (Exception e) {
					logger.error(e.toString());
				}
			}
		}
	}
}
