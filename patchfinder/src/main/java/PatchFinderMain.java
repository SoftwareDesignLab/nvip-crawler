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

import env.PatchFinderEnvVars;
import messenger.Messenger;
import messenger.PFInputMessage;
import model.CpeGroup;

import java.io.IOException;
import java.util.List;
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

    /**
     * Entry point for the PatchFinder, initializes necessary classes and start listening for jobs with RabbitMQ
     */
    @Override
    public void run() {
        logger.info("Starting PatchFinder...");
        // Init PatchFinder
        PatchFinder.init();

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
        Map<String, CpeGroup> affectedProducts = PatchFinder.getDatabaseHelper().getAffectedProducts(null);
        final int affectedProductsCount = affectedProducts.values().stream().map(CpeGroup::getVersionsCount).reduce(0, Integer::sum);
        logger.info("Successfully got {} CVEs mapped to {} affected products from the database", affectedProducts.size(), affectedProductsCount);
        try {
            PatchFinder.run(affectedProducts, PatchFinderEnvVars.getCveLimit());
        } catch (IOException e) {
            logger.error("A fatal error attempting to complete jobs: {}", e.toString());
        }
    }

    private void runRabbit() {
        // Start busy-wait loop
        final Messenger rabbitMQ = new Messenger(
                PatchFinderEnvVars.getRabbitHost(),
                PatchFinderEnvVars.getRabbitVHost(),
                    PatchFinderEnvVars.getRabbitPort(),PatchFinderEnvVars.getRabbitUsername(),
                PatchFinderEnvVars.getRabbitPassword(),
                    PatchFinderEnvVars.getRabbitInputQueue()
        );
        logger.info("Starting busy-wait loop for jobs...");
        while(true) {
            try {
                // Wait and get jobs
                final PFInputMessage msg = rabbitMQ.waitForProductNameExtractorMessage(PatchFinderEnvVars.getRabbitPollInterval());

                // If null is returned, either and error occurred or intentional program quit
                if(msg == null) break;

                // Otherwise, run received jobs
                PatchFinder.run(msg.getJobs());
            } catch (IOException | InterruptedException e) {
                logger.error("A fatal error occurred during job waiting: {}", e.toString());
                break;
            }
        }
    }
}
