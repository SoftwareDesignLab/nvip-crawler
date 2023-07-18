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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Map;

/**
 * Environment Variable Initialization class for Product Name Extractor.
 * Provides static access to all environment variables throughout the program.
 *
 * @author Dylan Mulligan
 */

public class PatchFinderEnvVars {
    private static final Logger logger = LogManager.getLogger(PatchFinderEnvVars.class);

    // Default values for main environment variables

    private static int cveLimit = 20;
    private static int maxThreads = 10;
    private static int cvesPerThread = 1;
    private static String databaseType = "mysql";
    private static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    private static String hikariUser = "root";
    private static String hikariPassword = "root";
    private static int cloneCommitThreshold = 1000; // TODO: Find omptimal value once github scraping is working well
    private static final int cloneCommitLimit = 50000; // TODO: Find omptimal value once github scraping is working well
    private static String clonePath = "patchfinder/src/main/resources/patch-repos";
    private static final String patchSrcUrlPath = "patchfinder/src/main/resources/source_dict.json";

    // Default values for database environment variables

    private static String databaseType = "mysql";
    private static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    private static String hikariUser = "root";
    private static String hikariPassword = "root";

    // Default values for rabbit environment variables

    private static int rabbitPollInterval = 10;
    private static String rabbitHost = "localhost";
    private static String rabbitUsername = "guest";
    private static String rabbitPassword = "guest";

    // Automatically load env vars
    static{
        initializeEnvVars();
    }

    // Manually load env vars
    public static void initializeEnvVars() {
        logger.info("Initializing Environment Variables...");
        fetchEnvVars();
    }

    // Getters

    public static String getRabbitHost() { return rabbitHost; }
    public static String getRabbitUsername() { return rabbitUsername; }
    public static String getRabbitPassword() { return rabbitPassword; }

    /**
     * Attempts to fetch all required environment variables from System.getenv() safely, logging
     * any missing or incorrect variables.
     */
    private static void fetchEnvVars() {
        // Fetch ENV_VARS and set all found configurable properties
        final Map<String, String> props = System.getenv();


        fetchHikariEnvVars(props);
        fetchRabbitEnvVars(props);
    }

    /**
     * Initialize database env vars
     *
     * @param props map of env vars
     */
    private static void fetchHikariEnvVars(Map<String, String> props) {
        if(props.containsKey("DB_TYPE")) {
            databaseType = System.getenv("DB_TYPE");
            logger.info("Setting DB_TYPE to {}", databaseType);
        } else logger.warn("Could not fetch DB_TYPE from env vars, defaulting to {}", databaseType);

        if(props.containsKey("HIKARI_URL")) {
            hikariUrl = System.getenv("HIKARI_URL");
            logger.info("Setting HIKARI_URL to {}", hikariUrl);
        } else logger.warn("Could not fetch HIKARI_URL from env vars, defaulting to {}", hikariUrl);

        if(props.containsKey("HIKARI_USER")) {
            hikariUser = System.getenv("HIKARI_USER");
            logger.info("Setting HIKARI_USER to {}", hikariUser);
        } else logger.warn("Could not fetch HIKARI_USER from env vars, defaulting to {}", hikariUser);

        if(props.containsKey("HIKARI_PASSWORD")) {
            hikariPassword = System.getenv("HIKARI_PASSWORD");
            logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
        } else logger.warn("Could not fetch HIKARI_PASSWORD from env vars, defaulting to {}", hikariPassword);
    }

    /**
     * Initialize RabbitMQ env vars
     *
     * @param props map of env vars
     */
    private static void fetchRabbitEnvVars(Map<String, String> props) {
        if(props.containsKey("RABBIT_HOST")) {
            rabbitHost = System.getenv("RABBIT_HOST");
            logger.info("Setting RABBIT_HOST to {}", rabbitHost);
        } else logger.warn("Could not fetch RABBIT_HOST from env vars, defaulting to {}", rabbitHost);

        if(props.containsKey("RABBIT_USERNAME")) {
            rabbitUsername = System.getenv("RABBIT_USERNAME");
            logger.info("Setting RABBIT_USERNAME to {}", rabbitUsername);
        } else logger.warn("Could not fetch RABBIT_USERNAME from env vars, defaulting to {}", rabbitUsername);

        if(props.containsKey("RABBIT_PASSWORD")) {
            rabbitPassword = System.getenv("RABBIT_PASSWORD");
            logger.info("Setting RABBIT_PASSWORD to {}", rabbitPassword);
        } else logger.warn("Could not fetch RABBIT_PASSWORD from env vars, defaulting to {}", rabbitPassword);
        if(props.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(System.getenv("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {}", rabbitPollInterval);
        } else logger.warn("Could not fetch RABBIT_POLL_INTERVAL from env vars, defaulting to {}", rabbitPollInterval);
    }
}
