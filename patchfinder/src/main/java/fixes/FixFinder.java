package fixes;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.repositories.PatchFixRepository;
import edu.rit.se.nvip.db.model.Fix;
import env.FixFinderEnvVars;
import fixes.urlfinders.FixUrlFinder;
import fixes.urlfinders.NvdFixUrlFinder;
import fixes.urlfinders.VulnerabilityFixUrlFinder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Main class for FixFinder initialization and handles multithreaded
 * processing for finding and extracting fixes.
 *
 * @author Dylan Mulligan
 */
public class FixFinder {
	private static final Logger logger = LogManager.getLogger(FixFinder.class.getName());
	private static final ObjectMapper OM = new ObjectMapper();
	private static DatabaseHelper databaseHelper;
	private static final List<FixUrlFinder> fixURLFinders = new ArrayList<>();
	private static final ArrayList<Fix> fixes = new ArrayList<>();
	protected static int cveLimit = FixFinderEnvVars.getCveLimit();
	protected static int maxThreads = FixFinderEnvVars.getMaxThreads();

	public static DatabaseHelper getDatabaseHelper() { return databaseHelper; }
	public static ArrayList<Fix> getFixes() { return fixes; }

	/**
	 * Initialize the FixFinder and its subcomponents
	 */
	public static void init() {
		logger.info("Initializing FixFinder...");

		// Init db helper
		logger.info("Initializing DatabaseHelper...");
		databaseHelper = DatabaseHelper.getInstance();

		// Init FixUrlFinders
		logger.info("Initializing FixUrlFinders...");

		// Add the instances to the fixURLFinders list
		fixURLFinders.add(new VulnerabilityFixUrlFinder());
		fixURLFinders.add(new NvdFixUrlFinder());

		logger.info("Done initializing {} FixUrlFinders: {}", fixURLFinders.size(), fixURLFinders);
	}

	// TODO: at some point, need to figure out how we are going to get input for which cves to find fixes
	// 	right now, just doing a list of cveIds
	public static void run(List<String> cveIds) {
		PatchFixRepository pfRepo = new PatchFixRepository(databaseHelper.getDataSource());
		Map<String, List<String>> cveToUrls = new HashMap<>();
		ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()); // Adjust the thread pool size as needed
		List<Future<?>> futures = new ArrayList<>();

		for (String cveId : cveIds) {
			final List<String> sourceUrls = new ArrayList<>();
			try {
				for (FixUrlFinder finder : fixURLFinders) {
					final int prevUrlsNum = sourceUrls.size();
					sourceUrls.addAll(finder.run(cveId));
					logger.info("{} found {} potential fix urls for CVE: {}",
							finder.getClass().getSimpleName(),
							sourceUrls.size() - prevUrlsNum,
							cveId
					);
				}

			} catch (Exception e) {
				logger.info("Ran into error while finding URLs: {}", e.toString());
			}

			cveToUrls.put(cveId, sourceUrls);
		}

		for (String cveId : cveToUrls.keySet()) {
			Future<?> future = executorService.submit(() -> {
				FixFinderThread thread = new FixFinderThread(cveId, cveToUrls.get(cveId));
				thread.run();
			});
			futures.add(future);
		}

		// Wait for all threads to complete
		for (Future<?> future : futures) {
			try {
				// TODO: Fix NullPointerException here
				future.get(); // This will block until the thread is finished
			} catch (Exception e) {
				logger.error("Error occurred while executing a thread: {}", e.toString());
			}
		}

		executorService.shutdown();

		try {
			executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
		} catch (InterruptedException e) {
			logger.error("ExecutorService was interrupted: {}", e.toString());
		}

		// After all threads have been run, insert found fixes into the database
		int existingInserts = 0;
		int failedInserts = 0;

		for (Fix fix : fixes) {
			try {
				final int result = pfRepo.insertFix(fix);

				// Result of operation, 0 for OK, 1 for error, 2 for already exists
				switch (result) {
					case 2:
						existingInserts++;
						break;
					case 1:
						failedInserts++;
						break;
					default:
						break;
				}
			} catch (Exception e) {
				logger.error("Error occurred while inserting fix for CVE {} into the database: {}",
						fix.getCveId(),
						e.toString()
				);
			}
		}

		logger.info("Successfully inserted {} patch commits into the database ({} failed, {} already existed)",
				fixes.size() - failedInserts - existingInserts,
//				(System.currentTimeMillis() - insertPatchesStart) / 1000,
				failedInserts,
				existingInserts
		);
	}
}
