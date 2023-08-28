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
import env.FixFinderEnvVars;
import db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.*;

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
		databaseHelper = new DatabaseHelper(
				FixFinderEnvVars.getDatabaseType(),
				FixFinderEnvVars.getHikariUrl(),
				FixFinderEnvVars.getHikariUser(),
				FixFinderEnvVars.getHikariPassword()
		);

		// Init FixUrlFinders
		logger.info("Initializing FixUrlFinders...");

		// Add the instances to the fixURLFinders list
		fixURLFinders.add(new VulnerabilityFixUrlFinder());
		fixURLFinders.add(new NvdFixUrlFinder());

		logger.info("Done initializing {} FixUrlFinders", fixURLFinders.size());
	}

	// TODO: at some point, need to figure out how we are going to get input for which cves to find fixes
	// 	right now, just doing a list of cveIds
	public static void run(List<String> cveIds) {
		Map<String, List<String>> cveToUrls = new HashMap<>();

		for(String cveId : cveIds){
			try {
				for(FixUrlFinder finder : fixURLFinders){
					cveToUrls.put(cveId, finder.run(cveId));
				}

			} catch (Exception e) {
				logger.info("Ran into error while finding URLs: {}", e.toString());
			}
		}

		// TODO: handle multithreading correctly with futures ?
		for(String cveId : cveToUrls.keySet()){
			FixFinderThread thread = new FixFinderThread(cveId, cveToUrls.get(cveId));
			thread.run();
		}

		// After all threads have been run, insert found fixes into database
		for(Fix fix : fixes){
			try{
				// TODO: fix this method and update database schema (ask dylan/dylan do this)
				databaseHelper.insertFix(fix);
			} catch (Exception e) {
				logger.error("Error occurred while inserting fix for CVE {} into database!", fix.getCveId());
			}
		}


	}
}
