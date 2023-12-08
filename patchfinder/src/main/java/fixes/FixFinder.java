/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package fixes;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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
import edu.rit.se.nvip.db.repositories.VulnerabilityRepository;
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
	private static PatchFixRepository pfRepo;
	private static VulnerabilityRepository vulnRepo;
	private static final List<FixUrlFinder> fixURLFinders = new ArrayList<>();
	protected static int cveLimit = FixFinderEnvVars.getCveLimit();
	protected static int maxThreads = FixFinderEnvVars.getMaxThreads();

	public static DatabaseHelper getDatabaseHelper() { return databaseHelper; }

	/**
	 * Initialize the FixFinder and its subcomponents
	 */
	public static void init(DatabaseHelper dbh, PatchFixRepository pfRepo, VulnerabilityRepository vulnRepo) {
		logger.info("Initializing FixFinder...");

		// Init db helper
		logger.info("Initializing DatabaseHelper...");
		databaseHelper = dbh;
		FixFinder.pfRepo = pfRepo;
		FixFinder.vulnRepo = vulnRepo;

		// Init FixUrlFinders
		logger.info("Initializing FixUrlFinders...");

		// Add the instances to the fixURLFinders list
		fixURLFinders.add(new VulnerabilityFixUrlFinder());
		fixURLFinders.add(new NvdFixUrlFinder());

		logger.info("Done initializing {} FixUrlFinders: {}", fixURLFinders.size(), fixURLFinders);
	}

	// TODO: at some point, need to figure out how we are going to get input for which cves to find fixes
	// 	right now, just doing a list of cveIds
	public static void run(int vulnVersionId) {
		// Find fixes with multithreading (on sources)
		String cveId = vulnRepo.getCveIdFromVulnVersion(vulnVersionId);
		final Set<Fix> fixes = FixFinder.findFixesMultiThreaded(cveId);

		// Insert found fixes
		final int[] insertStats = pfRepo.insertFixes(fixes);
		final int failedInserts = insertStats[0];
		final int existingInserts = insertStats[1];

		logger.info("Successfully inserted {} patch commits into the database ({} failed, {} already existed)",
				fixes.size() - failedInserts - existingInserts,
				failedInserts,
				existingInserts
		);
	}

	private static Set<Fix> findFixesMultiThreaded(String cveId) {
		final Set<Fix> fixes = new HashSet<>();
		ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()); // Adjust the thread pool size as needed
		List<Future<Set<Fix>>> futures = new ArrayList<>();

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

		for (String source : sourceUrls) {
			Future<Set<Fix>> future = executorService.submit(() -> {
				FixFinderThread thread = new FixFinderThread(cveId, source);
				thread.run();
				return thread.getFixes();
			});
			futures.add(future);
		}

		// Wait for all threads to complete
		for (Future<Set<Fix>> future : futures) {
			try {
				fixes.addAll(future.get()); // This will block until the thread is finished
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

		return fixes;
	}

	@Override
	public String toString() {
		return this.getClass().getSimpleName();
	}
}
