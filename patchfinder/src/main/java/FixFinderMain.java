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

import env.FixFinderEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import fixes.FixFinder;

import java.util.ArrayList;
import java.util.List;

/**
 * Main class for the FixFinder, drives initialization and busy-waiting for jobs
 *
 * @author Dylan Mulligan
 */
public class FixFinderMain {
    private final static Logger logger = LogManager.getLogger(FixFinderMain.class);

    /**
     * Entry point for the FixFinder, initializes necessary classes and start listening for jobs with RabbitMQ
     */
    public static void run() {
        logger.info("Starting FixFinder...");

        // Init FixFinder
        FixFinder.init();

        // Determine run mode and start PatchFinder
        switch (FixFinderEnvVars.getInputMode()) {
            case "db":
                runDb();
                break;
            case "rabbit":
                runRabbit();
                break;
            default:
                logger.info("Skipping FixFinder as input mode is not set to a valid value... Set to a valid value to enable it.");
        }
    }

    private static void runDb() {
        // Just for testing
        List<String> cveIds = new ArrayList<>();
        cveIds.add("CVE-2022-2967");

        try {
            FixFinder.run(cveIds);
        } catch (Exception e) {
            logger.error("A fatal error attempting to complete jobs: {}", e.toString());
        }
    }

    private static void runRabbit() {
        // TODO: RabbitMQ integration, wait until PoC is accepted to complete this
    }

    public static void main(String[] args) {
        run();
    }
}
