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

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.repositories.PatchFixRepository;
import edu.rit.se.nvip.db.repositories.VulnerabilityRepository;
import env.FixFinderEnvVars;
import env.SharedEnvVars;
import messenger.Messenger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import fixes.FixFinder;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

/**
 * Main class for the FixFinder, drives initialization and busy-waiting for jobs
 *
 * @author Dylan Mulligan
 */
public class FixFinderMain extends Thread {
    private final static Logger logger = LogManager.getLogger(FixFinderMain.class);
    private final DatabaseHelper databaseHelper;
    private final Messenger messenger;

    public FixFinderMain(DatabaseHelper dbh, Messenger messenger) {
        this.databaseHelper = dbh;
        this.messenger = messenger;
    }

    /**
     * Entry point for the FixFinder, initializes necessary classes and start listening for jobs with RabbitMQ
     */
    @Override
    public void run() {
        logger.info("Starting FixFinder...");

        // Get input mode
        final String inputMode = FixFinderEnvVars.getInputMode();

        // Determine run mode and start PatchFinder
        switch (inputMode) {
            case "db":
                // Init FixFinder
                FixFinder.init(this.databaseHelper, new PatchFixRepository(databaseHelper.getDataSource()), new VulnerabilityRepository(databaseHelper.getDataSource()));
                runDb();
                break;
            case "rabbit":
                // Init FixFinder
                FixFinder.init(this.databaseHelper, new PatchFixRepository(databaseHelper.getDataSource()), new VulnerabilityRepository(databaseHelper.getDataSource()));
                runRabbit();
                break;
            case "dev":
                // Init FixFinder
                FixFinder.init(this.databaseHelper, new PatchFixRepository(databaseHelper.getDataSource()), new VulnerabilityRepository(databaseHelper.getDataSource()));
                runDev();
                break;
            default:
                logger.info("Skipping FixFinder as input mode is not set to a valid value... Set to a valid value to enable it.");
                break;
        }
    }

    private void runDb() {
        // Fetch cves from db
        VulnerabilityRepository vulnRepo = new VulnerabilityRepository(databaseHelper.getDataSource());
        List<Integer> versionIds = new ArrayList<>(vulnRepo.getCves(FixFinderEnvVars.getCveLimit()));
        logger.info("Successfully got {} CVEs from the database", versionIds.size());

        for (int versionId : versionIds) FixFinder.run(versionId);
    }

    // TODO: Support end message
    private void runRabbit() {
        // Start job handling
        messenger.startHandlingFixJobs(SharedEnvVars.getFixFinderInputQueue());
    }

    private void runDev() {
        // Manually enter CVEs for development
        List<Integer> versionIds = new ArrayList<>();
        versionIds.add(1234);

        for (int id : versionIds) FixFinder.run(id);
    }
}
