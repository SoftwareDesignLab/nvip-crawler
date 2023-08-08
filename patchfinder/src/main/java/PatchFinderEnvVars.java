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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Environment Variable Initialization class for Patchfinder.
 * Provides static access to all environment variables throughout the program.
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */

public class PatchFinderEnvVars {
    private static final Logger logger = LogManager.getLogger(PatchFinderEnvVars.class);
    private static final String envVarPath = "env.list";

    // Default values for main environment variables

    private static int cveLimit = 20;
    private static String[] addressBases = {"https://www.github.com/", "https://www.gitlab.com/"};
    private static int maxThreads = 10;
    private static int cloneCommitThreshold = 1000; // TODO: Find optimal value once github scraping is working well
    private static int cloneCommitLimit = 50000; // TODO: Find optimal value once github scraping is working well
    private static String clonePath = "nvip_data/patch-repos";
    private static String patchSrcUrlPath = "nvip_data/source_dict.json";

    // Default values for database environment variables

    private static String databaseType = "mysql";
    private static String hikariUrl = "jdbc:mysql://host.docker.internal:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    private static String hikariUser = "root";
    private static String hikariPassword = "root";

    // Default values for rabbit environment variables

    private static int rabbitPollInterval = 60;
    private static String rabbitHost = "host.docker.internal";
    private static String rabbitUsername = "guest";
    private static String rabbitPassword = "guest";

    // Automatically load env vars
    static{
        initializeEnvVars();
    }

    /**
     * Loads environment variables from both env.list file and System.getenv(). If both of these fail, resorts to
     * default values defined above. Prioritizes System.getenv() first and then from file second.
     */
    public static void initializeEnvVars() {
        logger.info("CURRENT PATH --> " + System.getProperty("user.dir"));
        logger.info("Initializing Environment Variables...");

        Map<String, String> fileProps = null;
        Map<String, String> systemProps = System.getenv();

        try {
            // Assumes in `nvip-crawler/patchfinder` working directory
            fileProps = loadEnvVarsFromFile(envVarPath);
        } catch (FileNotFoundException e){
            // If that path doesn't work, assumes we are in `nvip-crawler` directory and tries new path with `patchfinder` appended to it
            try{
                String possiblePath = "patchfinder\\" + envVarPath;
                fileProps = loadEnvVarsFromFile(possiblePath);
            } catch (Exception ignored) {}
        }

        // If env vars couldn't be loaded from file, pass in empty map
        if(fileProps == null) fileProps = new HashMap<>();
        fetchEnvVars(systemProps, fileProps);
    }

    // Getters

    public static int getCveLimit() { return cveLimit; }
    public static String[] getAddressBases() { return addressBases; }
    public static int getMaxThreads() { return maxThreads; }
    public static int getCloneCommitThreshold() { return cloneCommitThreshold; }
    public static int getCloneCommitLimit() { return cloneCommitLimit; }
    public static String getClonePath() { return clonePath; }
    public static String getPatchSrcUrlPath() { return patchSrcUrlPath; }
    public static String getDatabaseType() { return databaseType; }
    public static String getHikariUrl() { return hikariUrl; }
    public static String getHikariUser() { return hikariUser; }
    public static String getHikariPassword() { return hikariPassword; }
    public static int getRabbitPollInterval() { return rabbitPollInterval; }
    public static String getRabbitHost() { return rabbitHost; }
    public static String getRabbitUsername() { return rabbitUsername; }
    public static String getRabbitPassword() { return rabbitPassword; }

    /**
     * Loads environment variables from file into HashMap and returns it.
     *
     * @param path path to env.list file
     * @return map of environment variables
     */
    private static Map<String, String> loadEnvVarsFromFile(String path) throws FileNotFoundException {
        Map<String, String> props = new HashMap<>();

        try {
            FileReader fileReader = new FileReader(path);
            BufferedReader reader = new BufferedReader(fileReader);

            // Go through each line
            String line = reader.readLine();
            while (line != null) {
                // If it contains an equals sign, is an environment variable
                if (line.contains("=")) {
                    int index = line.indexOf('=');
                    // Add the env var and its value
                    props.put(line.substring(0, index), line.substring(index + 1));
                }

                line = reader.readLine();
            }

        } catch(FileNotFoundException e){
            throw e;
        } catch (IOException e){
            logger.error("Reading from environment variable file failed with error {}", e.toString());
        }

        return props;

    }

    /**
     * Attempts to fetch all required environment variables from props map safely, logging any
     * missing or incorrect variables.
     *
     * If environment variable is not found from System.getenv(), it will attempt to fetch it from the loaded file. If it
     * is still not found, it will resort to default value. Priority: System.getenv() <- env.list file <- default values
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchEnvVars(Map<String, String> systemProps, Map<String, String> fileProps) {

        if(systemProps.containsKey("CVE_LIMIT")) {
            cveLimit = Integer.parseInt(systemProps.get("CVE_LIMIT"));
            logger.info("Setting CVE_LIMIT to {}", cveLimit);
        } else if (fileProps.containsKey("CVE_LIMIT")) {
            cveLimit = Integer.parseInt(fileProps.get("CVE_LIMIT"));
            logger.info("Setting CVE_LIMIT to {}", cveLimit);
        } else logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to {}", cveLimit);

        if(systemProps.containsKey("ADDRESS_BASES")) {
            addressBases = systemProps.get("ADDRESS_BASES").split(",");
            logger.info("Setting ADDRESS_BASES to {}", Arrays.toString(addressBases));
        } else if (fileProps.containsKey("ADDRESS_BASES")) {
            addressBases = fileProps.get("ADDRESS_BASES").split(",");
            logger.info("Setting ADDRESS_BASES to {}", Arrays.toString(addressBases));
        } else logger.warn("Could not fetch ADDRESS_BASES from env vars, defaulting to {}", addressBases);

        if(systemProps.containsKey("MAX_THREADS")) {
            maxThreads = Integer.parseInt(systemProps.get("MAX_THREADS"));
            logger.info("Setting MAX_THREADS to {}", maxThreads);
        } else if (fileProps.containsKey("MAX_THREADS")) {
            maxThreads = Integer.parseInt(fileProps.get("MAX_THREADS"));
            logger.info("Setting MAX_THREADS to {}", maxThreads);
        } else logger.warn("Could not fetch MAX_THREADS from env vars, defaulting to {}", maxThreads);

        if(systemProps.containsKey("CLONE_COMMIT_THRESHOLD")) {
            cloneCommitThreshold = Integer.parseInt(systemProps.get("CLONE_COMMIT_THRESHOLD"));
            logger.info("Setting CLONE_COMMIT_THRESHOLD to {}", cloneCommitThreshold);
        } else if (fileProps.containsKey("CLONE_COMMIT_THRESHOLD")) {
            cloneCommitThreshold = Integer.parseInt(fileProps.get("CLONE_COMMIT_THRESHOLD"));
            logger.info("Setting CLONE_COMMIT_THRESHOLD to {}", cloneCommitThreshold);
        } else logger.warn("Could not fetch CLONE_COMMIT_THRESHOLD from env vars, defaulting to {}", cloneCommitThreshold);

        if(systemProps.containsKey("CLONE_COMMIT_LIMIT")) {
            cloneCommitLimit = Integer.parseInt(systemProps.get("CLONE_COMMIT_LIMIT"));
            logger.info("Setting CLONE_COMMIT_LIMIT to {}", cloneCommitLimit);
        } else if (fileProps.containsKey("CLONE_COMMIT_LIMIT")) {
            cloneCommitLimit = Integer.parseInt(fileProps.get("CLONE_COMMIT_LIMIT"));
            logger.info("Setting CLONE_COMMIT_LIMIT to {}", cloneCommitLimit);
        } else logger.warn("Could not fetch CLONE_COMMIT_LIMIT from env vars, defaulting to {}", cloneCommitLimit);

        if(systemProps.containsKey("CLONE_PATH")) {
            clonePath = systemProps.get("CLONE_PATH");
            logger.info("Setting CLONE_PATH to {}", clonePath);
        } else if (fileProps.containsKey("CLONE_PATH")) {
            clonePath = fileProps.get("CLONE_PATH");
            logger.info("Setting CLONE_PATH to {}", clonePath);
        } else logger.warn("Could not fetch CLONE_PATH from env vars, defaulting to {}", clonePath);

        if(systemProps.containsKey("PATCH_SRC_URL_PATH")) {
            patchSrcUrlPath = systemProps.get("PATCH_SRC_URL_PATH");
            logger.info("Setting PATCH_SRC_URL_PATH to {}", patchSrcUrlPath);
        } else if (fileProps.containsKey("PATCH_SRC_URL_PATH")) {
            patchSrcUrlPath = fileProps.get("PATCH_SRC_URL_PATH");
            logger.info("Setting PATCH_SRC_URL_PATH to {}", patchSrcUrlPath);
        } else logger.warn("Could not fetch PATCH_SRC_URL_PATH from env vars, defaulting to {}", patchSrcUrlPath);

        fetchHikariEnvVars(systemProps, fileProps);
        fetchRabbitEnvVars(systemProps, fileProps);

    }

    /**
     * Initialize database env vars
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchHikariEnvVars(Map<String, String> systemProps, Map<String, String> fileProps) {

        if(systemProps.containsKey("DB_TYPE")) {
            databaseType = systemProps.get("DB_TYPE");
            logger.info("Setting DB_TYPE to {}", databaseType);
        } else if (fileProps.containsKey("DB_TYPE")) {
            databaseType = fileProps.get("DB_TYPE");
            logger.info("Setting DB_TYPE to {}", databaseType);
        } else logger.warn("Could not fetch DB_TYPE from env vars, defaulting to {}", databaseType);

        if(systemProps.containsKey("HIKARI_URL")) {
            hikariUrl = systemProps.get("HIKARI_URL");
            logger.info("Setting HIKARI_URL to {}", hikariUrl);
        } else if (fileProps.containsKey("HIKARI_URL")) {
            hikariUrl = fileProps.get("HIKARI_URL");
            logger.info("Setting HIKARI_URL to {}", hikariUrl);
        } else logger.warn("Could not fetch HIKARI_URL from env vars, defaulting to {}", hikariUrl);

        if(systemProps.containsKey("HIKARI_USER")) {
            hikariUser = systemProps.get("HIKARI_USER");
            logger.info("Setting HIKARI_USER to {}", hikariUser);
        } else if (fileProps.containsKey("HIKARI_USER")) {
            hikariUser = fileProps.get("HIKARI_USER");
            logger.info("Setting HIKARI_USER to {}", hikariUser);
        } else logger.warn("Could not fetch HIKARI_USER from env vars, defaulting to {}", hikariUser);

        if(systemProps.containsKey("HIKARI_PASSWORD")) {
            hikariPassword = systemProps.get("HIKARI_PASSWORD");
            logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
        } else if (fileProps.containsKey("HIKARI_PASSWORD")) {
            hikariPassword = fileProps.get("HIKARI_PASSWORD");
            logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
        } else logger.warn("Could not fetch HIKARI_PASSWORD from env vars, defaulting to {}", hikariPassword);

    }

    /**
     * Initialize RabbitMQ env vars
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchRabbitEnvVars(Map<String, String> systemProps, Map<String, String> fileProps) {

        if(systemProps.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(systemProps.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {}", rabbitPollInterval);
        } else if (fileProps.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(fileProps.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {}", rabbitPollInterval);
        } else logger.warn("Could not fetch RABBIT_POLL_INTERVAL from env vars, defaulting to {}", rabbitPollInterval);

        if(systemProps.containsKey("RABBIT_HOST")) {
            rabbitHost = systemProps.get("RABBIT_HOST");
            logger.info("Setting RABBIT_HOST to {}", rabbitHost);
        } else if (fileProps.containsKey("RABBIT_HOST")) {
            rabbitHost = fileProps.get("RABBIT_HOST");
            logger.info("Setting RABBIT_HOST to {}", rabbitHost);
        } else logger.warn("Could not fetch RABBIT_HOST from env vars, defaulting to {}", rabbitHost);

        if(systemProps.containsKey("RABBIT_USERNAME")) {
            rabbitUsername = systemProps.get("RABBIT_USERNAME");
            logger.info("Setting RABBIT_USERNAME to {}", rabbitUsername);
        } else if (fileProps.containsKey("RABBIT_USERNAME")) {
            rabbitUsername = fileProps.get("RABBIT_USERNAME");
            logger.info("Setting RABBIT_USERNAME to {}", rabbitUsername);
        } else logger.warn("Could not fetch RABBIT_USERNAME from env vars, defaulting to {}", rabbitUsername);

        if(systemProps.containsKey("RABBIT_PASSWORD")) {
            rabbitPassword = systemProps.get("RABBIT_PASSWORD");
            logger.info("Setting RABBIT_PASSWORD to {}", rabbitPassword);
        } else if (fileProps.containsKey("RABBIT_PASSWORD")) {
            rabbitPassword = fileProps.get("RABBIT_PASSWORD");
            logger.info("Setting RABBIT_PASSWORD to {}", rabbitPassword);
        } else logger.warn("Could not fetch RABBIT_PASSWORD from env vars, defaulting to {}", rabbitPassword);

    }
}
