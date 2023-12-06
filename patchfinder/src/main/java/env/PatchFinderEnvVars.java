package env;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static env.EnvVarLoader.loadEnvVarsFromFile;

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

    private static String inputMode = "db";
    private static int cveLimit = 20;
    private static String[] addressBases = {"https://www.github.com/", "https://www.gitlab.com/"};
    private static int maxThreads = 10;
    private static int cloneCommitThreshold = 250;
    private static int cloneCommitLimit = 200000;
    private static String clonePath = "nvip_data/patch-repos";
    private static String patchSrcUrlPath = "nvip_data/source_dict.json";

    // Automatically load env vars
    static{
        initializeEnvVars(false);
    }

    /**
     * Loads environment variables from both env.list file and System.getenv(). If both of these fail, resorts to
     * default values defined above. Prioritizes System.getenv() first and then from file second.
     */
    public static void initializeEnvVars(boolean testMode) {
        logger.info("CURRENT PATH --> " + System.getProperty("user.dir"));
        if(testMode) logger.info("Initializing Test Environment Variables...");
        else logger.info("Initializing Environment Variables...");

        Map<String, String> fileProps = null;
        Map<String, String> systemProps = System.getenv();
        String filePath = envVarPath;
        if(testMode) filePath = "src/test/" + filePath;

        try {
            // Assumes in `nvip-crawler/patchfinder` working directory
            fileProps = loadEnvVarsFromFile(filePath);
        } catch (FileNotFoundException e){
            // If that path doesn't work, assumes we are in `nvip-crawler` directory and tries new path with `patchfinder` appended to it
            try{
                String possiblePath = "patchfinder\\" + filePath;
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
    public static String getInputMode() { return inputMode; }

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

        if(systemProps.containsKey("PF_INPUT_MODE")) {
            inputMode = systemProps.get("PF_INPUT_MODE");
            logger.info("Setting PF_INPUT_MODE to {}", inputMode);
        } else if (fileProps.containsKey("PF_INPUT_MODE")) {
            inputMode = fileProps.get("PF_INPUT_MODE");
            logger.info("Setting PF_INPUT_MODE to {}", inputMode);
        } else logger.warn("Could not fetch PF_INPUT_MODE from env vars, defaulting to {}", inputMode);

        if(systemProps.containsKey("CVE_LIMIT")) {
            cveLimit = Integer.parseInt(systemProps.get("CVE_LIMIT"));
            logger.info("Setting CVE_LIMIT to {} CVEs", cveLimit);
        } else if (fileProps.containsKey("CVE_LIMIT")) {
            cveLimit = Integer.parseInt(fileProps.get("CVE_LIMIT"));
            logger.info("Setting CVE_LIMIT to {} CVEs", cveLimit);
        } else logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to {} CVEs", cveLimit);

        if(systemProps.containsKey("ADDRESS_BASES")) {
            addressBases = systemProps.get("ADDRESS_BASES").split(",");
            logger.info("Setting ADDRESS_BASES to {}", Arrays.toString(addressBases));
        } else if (fileProps.containsKey("ADDRESS_BASES")) {
            addressBases = fileProps.get("ADDRESS_BASES").split(",");
            logger.info("Setting ADDRESS_BASES to {}", Arrays.toString(addressBases));
        } else logger.warn("Could not fetch ADDRESS_BASES from env vars, defaulting to {}", addressBases);

        if(systemProps.containsKey("MAX_THREADS")) {
            maxThreads = Integer.parseInt(systemProps.get("MAX_THREADS"));
            logger.info("Setting MAX_THREADS to {} threads", maxThreads);
        } else if (fileProps.containsKey("MAX_THREADS")) {
            maxThreads = Integer.parseInt(fileProps.get("MAX_THREADS"));
            logger.info("Setting MAX_THREADS to {} threads", maxThreads);
        } else logger.warn("Could not fetch MAX_THREADS from env vars, defaulting to {} threads", maxThreads);

        if(systemProps.containsKey("CLONE_COMMIT_THRESHOLD")) {
            cloneCommitThreshold = Integer.parseInt(systemProps.get("CLONE_COMMIT_THRESHOLD"));
            logger.info("Setting CLONE_COMMIT_THRESHOLD to {} commits", cloneCommitThreshold);
        } else if (fileProps.containsKey("CLONE_COMMIT_THRESHOLD")) {
            cloneCommitThreshold = Integer.parseInt(fileProps.get("CLONE_COMMIT_THRESHOLD"));
            logger.info("Setting CLONE_COMMIT_THRESHOLD to {} commits", cloneCommitThreshold);
        } else logger.warn("Could not fetch CLONE_COMMIT_THRESHOLD from env vars, defaulting to {} commits", cloneCommitThreshold);

        if(systemProps.containsKey("CLONE_COMMIT_LIMIT")) {
            cloneCommitLimit = Integer.parseInt(systemProps.get("CLONE_COMMIT_LIMIT"));
            logger.info("Setting CLONE_COMMIT_LIMIT to {} commits", cloneCommitLimit);
        } else if (fileProps.containsKey("CLONE_COMMIT_LIMIT")) {
            cloneCommitLimit = Integer.parseInt(fileProps.get("CLONE_COMMIT_LIMIT"));
            logger.info("Setting CLONE_COMMIT_LIMIT to {} commits", cloneCommitLimit);
        } else logger.warn("Could not fetch CLONE_COMMIT_LIMIT from env vars, defaulting to {} commits", cloneCommitLimit);

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
    }
}
