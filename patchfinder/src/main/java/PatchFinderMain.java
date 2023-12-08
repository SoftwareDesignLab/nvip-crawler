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
import edu.rit.se.nvip.db.model.CpeGroup;
import edu.rit.se.nvip.db.repositories.PatchFixRepository;
import edu.rit.se.nvip.db.repositories.ProductRepository;
import edu.rit.se.nvip.db.repositories.VulnerabilityRepository;
import env.PatchFinderEnvVars;
import env.SharedEnvVars;
import messenger.Messenger;

import java.io.IOException;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import patches.PatchFinder;

/**
 * Main class for the PatchFinder, drives initialization and busy-waiting for jobs
 *
 * @author Dylan Mulligan
 */
public class PatchFinderMain extends Thread {
    private final static Logger logger = LogManager.getLogger(PatchFinderMain.class);
    private final DatabaseHelper databaseHelper;
    private final Messenger messenger;

    public PatchFinderMain(DatabaseHelper dbh, Messenger messenger) {
        this.databaseHelper = dbh;
        this.messenger = messenger;
    }

    /**
     * Entry point for the PatchFinder, initializes necessary classes and start listening for jobs with RabbitMQ
     */
    @Override
    public void run() {
        logger.info("Starting PatchFinder...");
        // Init PatchFinder
        PatchFinder.init(this.databaseHelper, new ProductRepository(this.databaseHelper.getDataSource()), new PatchFixRepository(this.databaseHelper.getDataSource()));

        // Determine run mode and start PatchFinder
        switch (PatchFinderEnvVars.getInputMode()) {
            case "db":
                runDb();
                break;
            case "rabbit":
                runRabbit();
                break;
            default:
                logger.info("Skipping PatchFinder as input mode is not set to a valid value... Set to a valid value to enable it.");
                break;
        }
    }

    private void runDb() {
        // Fetch affectedProducts from db
        ProductRepository prodRepo = new ProductRepository(PatchFinder.getDatabaseHelper().getDataSource());
        Map<String, CpeGroup> affectedProducts = prodRepo.getAffectedProducts(-1);
        final int affectedProductsCount = affectedProducts.values().stream().map(CpeGroup::getVersionsCount).reduce(0, Integer::sum);
        logger.info("Successfully got {} CVEs mapped to {} affected products from the database", affectedProducts.size(), affectedProductsCount);
        try {
            // TODO: Delegate to threads
            for (String cveId : affectedProducts.keySet()) {
                PatchFinder.run(cveId, affectedProducts.get(cveId));
            }

            // When all threads are done, write source dict to file
            PatchFinder.writeSourceDict();
        } catch (IOException e) {
            logger.error("A fatal error attempting to complete jobs: {}", e.toString());
        }
    }

    // TODO: Support end message
    private void runRabbit() {
        // Start job handling
        messenger.startHandlingPatchJobs(SharedEnvVars.getPatchFinderInputQueue());
    }
}
