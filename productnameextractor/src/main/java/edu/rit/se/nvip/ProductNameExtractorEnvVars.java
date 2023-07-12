package edu.rit.se.nvip;

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
 * Environment Variable Initialization class for Product Name Extractor
 *
 * @author Paul Vickers
 */
public class ProductNameExtractorEnvVars {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorEnvVars.class);

    /**
     * Default values for environment variables
     */
    private static int rabbitPollInterval = 10;
    private static int numThreads = 12;
    private static String databaseType = "mysql";
    private static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    private static String hikariUser = "root";
    private static String hikariPassword = "root";
    private static int maxPages = 10;
    private static int maxAttemptsPerPage = 2;
    private static boolean prettyPrint = false;
    private static boolean testMode = false;
    private static String productDictName = "product_dict.json";
    private static String resourceDir = "productnameextractor/nvip_data";
    private static String dataDir = "data";
    private static String nlpDir = "nlp";

    static{
        logger.info("Initializing Environment Variables...");
        fetchEnvVars();
    }

    public static int getRabbitPollInterval() {
        return rabbitPollInterval;
    }

    public static int getNumThreads() {
        return numThreads;
    }

    public static String getDatabaseType() {
        return databaseType;
    }

    public static String getHikariUrl() {
        return hikariUrl;
    }

    public static String getHikariUser() {
        return hikariUser;
    }

    public static String getHikariPassword() {
        return hikariPassword;
    }

    public static int getMaxPages() {
        return maxPages;
    }

    public static int getMaxAttemptsPerPage() {
        return maxAttemptsPerPage;
    }

    public static boolean isPrettyPrint() {
        return prettyPrint;
    }

    public static boolean isTestMode() {
        return testMode;
    }

    public static String getProductDictName() {
        return productDictName;
    }

    public static String getResourceDir() {
        return resourceDir;
    }

    public static String getDataDir() {
        return dataDir;
    }

    public static String getNlpDir() {
        return nlpDir;
    }

    /**
     * Attempts to get all required environment variables from System.getenv() safely, logging
     * any missing or incorrect variables.
     */
    private static void fetchEnvVars() {
        // Fetch ENV_VARS and set all found configurable properties
        final Map<String, String> props = System.getenv();

        if(props.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(System.getenv("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {}", rabbitPollInterval);
        } else logger.warn("Could not fetch RABBIT_POLL_INTERVAL from env vars, defaulting to {}", rabbitPollInterval);

        if(props.containsKey("NUM_THREADS")) {
            numThreads = Integer.parseInt(System.getenv("NUM_THREADS"));
            logger.info("Setting NUM_THREADS to {}", numThreads);
        } else logger.warn("Could not fetch NUM_THREADS from env vars, defaulting to {}", numThreads);

        if(props.containsKey("MAX_PAGES")) {
            maxPages = Integer.parseInt(System.getenv("MAX_PAGES"));
            logger.info("Setting MAX_PAGES to {}", maxPages);
        } else logger.warn("Could not fetch MAX_PAGES from env vars, defaulting to {}", maxPages);

        if(props.containsKey("MAX_ATTEMPTS_PER_PAGE")) {
            maxAttemptsPerPage = Integer.parseInt(System.getenv("MAX_ATTEMPTS_PER_PAGE"));
            logger.info("Setting MAX_ATTEMPTS_PER_PAGE to {}", maxAttemptsPerPage);
        } else logger.warn("Could not fetch MAX_ATTEMPTS_PER_PAGE from env vars, defaulting to {}", maxAttemptsPerPage);

        if(props.containsKey("PRODUCT_DICT_NAME")) {
            productDictName = System.getenv("PRODUCT_DICT_NAME");
            logger.info("Setting PRODUCT_DICT_NAME to {}", productDictName);
        } else logger.warn("Could not fetch PRODUCT_DICT_NAME from env vars, defaulting to {}", productDictName);

        if(props.containsKey("RESOURCE_DIR")) {
            resourceDir = System.getenv("RESOURCE_DIR");
            logger.info("Setting RESOURCE_DIR to {}", resourceDir);
        } else logger.warn("Could not fetch RESOURCE_DIR from env vars, defaulting to {}", resourceDir);

        if(props.containsKey("DATA_DIR")) {
            dataDir = System.getenv("DATA_DIR");
            logger.info("Setting DATA_DIR to {}", dataDir);
        } else logger.warn("Could not fetch DATA_DIR from env vars, defaulting to {}", dataDir);

        if(props.containsKey("NLP_DIR")) {
            nlpDir = System.getenv("NLP_DIR");
            logger.info("Setting NLP_DIR to {}", nlpDir);
        } else logger.warn("Could not fetch NLP_DIR from env vars, defaulting to {}", nlpDir);

        if(props.containsKey("PRETTY_PRINT")) {
            prettyPrint = Boolean.parseBoolean(System.getenv("PRETTY_PRINT"));
            logger.info("Setting PRETTY_PRINT to {}", prettyPrint);
        } else logger.warn("Could not fetch PRETTY_PRINT from env vars, defaulting to {}", prettyPrint);

        if(props.containsKey("TEST_MODE")) {
            testMode = Boolean.parseBoolean(System.getenv("TEST_MODE"));
            logger.info("Setting TEST_MODE to {}", testMode);
        } else logger.warn("Could not fetch TEST_MODE from env vars, defaulting to {}", testMode);

        fetchHikariEnvVars(props);
    }

    /**
     * Initialize database env vars
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
}
