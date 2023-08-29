package env;

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
import java.util.HashMap;
import java.util.Map;

/**
 * Environment Variable Initialization class for Product Name Extractor.
 * Provides static access to all environment variables throughout the program.
 *
 * @author Paul Vickers
 */

public class ProductNameExtractorEnvVars {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorEnvVars.class);
    private static final String envVarPath = "env.list";

    // Default values for main environment variables

    private static int numThreads = 12;
    private static String resourceDir = "nvip_data";
    private static String dataDir = "data";
    private static String nlpDir = "nlp";

    // Default values for Product Dictionary environment variables

    private static int maxAttemptsPerPage = 5;
    private static boolean prettyPrint = false;
    private static boolean testMode = false;
    private static String productDictName = "product_dict.json";
    private static float refreshInterval = 1;
    private static float fullPullInterval = 14;

    // Default values for database environment variables

    private static String databaseType = "mysql";
    private static String hikariUrl = "jdbc:mysql://host.docker.internal:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    private static String hikariUser = "root";
    private static String hikariPassword = "root";

    // Default values for model environment variables

    private static String productDetectorModel = "en-pos-perceptron.bin";
    private static String char2VecConfig = "c2v_model_config_50.json";
    private static String char2VecWeights = "c2v_model_weights_50.h5";
    private static String word2Vec = "w2v_model_250.bin";
    private static String nerModel = "NERallModel.bin";
    private static String nerModelNormalizer = "NERallNorm.bin";
    private static String sentenceModel = "en-sent.bin";

    // Default values for RabbitMQ environment variables

    private static int rabbitPollInterval = 60;
    private static String rabbitHost = "host.docker.internal";
    private static String rabbitUsername = "guest";
    private static String rabbitPassword = "guest";
    private static String rabbitInputQueue = "RECONCILER_OUT";
    private static String rabbitOutputQueue = "PNE_OUT";

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
            // Assumes in `nvip-crawler/productnameextractor` working directory
            fileProps = loadEnvVarsFromFile(envVarPath);
        } catch (FileNotFoundException e){
            // If that path doesn't work, assumes we are in `nvip-crawler` directory and tries new path with `productnameextractor` appended to it
            try{
                String possiblePath = "productnameextractor\\" + envVarPath;
                fileProps = loadEnvVarsFromFile(possiblePath);
            } catch (Exception ignored) {}
        }

        // If env vars couldn't be loaded from file, pass in empty map
        if(fileProps == null) fileProps = new HashMap<>();
        fetchEnvVars(systemProps, fileProps);
    }

    // Getters

    public static int getRabbitPollInterval() { return rabbitPollInterval; }
    public static int getNumThreads() { return numThreads; }
    public static String getDatabaseType() { return databaseType; }
    public static String getHikariUrl() { return hikariUrl; }
    public static String getHikariUser() { return hikariUser; }
    public static String getHikariPassword() { return hikariPassword; }
    public static int getMaxAttemptsPerPage() { return maxAttemptsPerPage; }
    public static boolean isPrettyPrint() { return prettyPrint; }
    public static boolean isTestMode() { return testMode; }
    public static String getProductDictName() { return productDictName; }
    public static float getRefreshInterval() { return refreshInterval; }
    public static float getFullPullInterval() { return fullPullInterval; }
    public static String getResourceDir() { return resourceDir; }
    public static String getDataDir() { return dataDir; }
    public static String getNlpDir() { return nlpDir; }
    public static String getProductDetectorModel() { return productDetectorModel; }
    public static String getChar2VecConfig() { return char2VecConfig; }
    public static String getChar2VecWeights() { return char2VecWeights; }
    public static String getWord2Vec() { return word2Vec; }
    public static String getNerModel() { return nerModel; }
    public static String getNerModelNormalizer() { return nerModelNormalizer; }
    public static String getSentenceModel() { return sentenceModel; }
    public static String getRabbitHost() { return rabbitHost; }
    public static String getRabbitUsername() { return rabbitUsername; }
    public static String getRabbitPassword() { return rabbitPassword; }
    public static String getRabbitInputQueue() { return rabbitInputQueue; }
    public static String getRabbitOutputQueue() { return rabbitOutputQueue; }

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

        if(systemProps.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(systemProps.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {} seconds", rabbitPollInterval);
        } else if (fileProps.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(fileProps.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {} seconds", rabbitPollInterval);
        } else logger.warn("Could not fetch RABBIT_POLL_INTERVAL from env vars, defaulting to {} seconds", rabbitPollInterval);

        if(systemProps.containsKey("NUM_THREADS")) {
            numThreads = Integer.parseInt(systemProps.get("NUM_THREADS"));
            logger.info("Setting NUM_THREADS to {} threads", numThreads);
        } else if (fileProps.containsKey("NUM_THREADS")) {
            numThreads = Integer.parseInt(fileProps.get("NUM_THREADS"));
            logger.info("Setting NUM_THREADS to {} threads", numThreads);
        } else logger.warn("Could not fetch NUM_THREADS from env vars, defaulting to {} threads", numThreads);

        if(systemProps.containsKey("MAX_ATTEMPTS_PER_PAGE")) {
            maxAttemptsPerPage = Integer.parseInt(systemProps.get("MAX_ATTEMPTS_PER_PAGE"));
            logger.info("Setting MAX_ATTEMPTS_PER_PAGE to {} attempts", maxAttemptsPerPage);
        } else if (fileProps.containsKey("MAX_ATTEMPTS_PER_PAGE")) {
            maxAttemptsPerPage = Integer.parseInt(fileProps.get("MAX_ATTEMPTS_PER_PAGE"));
            logger.info("Setting MAX_ATTEMPTS_PER_PAGE to {} attempts", maxAttemptsPerPage);
        } else logger.warn("Could not fetch MAX_ATTEMPTS_PER_PAGE from env vars, defaulting to {} attempts", maxAttemptsPerPage);

        if(systemProps.containsKey("PRODUCT_DICT_NAME")) {
            productDictName = systemProps.get("PRODUCT_DICT_NAME");
            logger.info("Setting PRODUCT_DICT_NAME to {}", productDictName);
        } else if (fileProps.containsKey("PRODUCT_DICT_NAME")) {
            productDictName = fileProps.get("PRODUCT_DICT_NAME");
            logger.info("Setting PRODUCT_DICT_NAME to {}", productDictName);
        } else logger.warn("Could not fetch PRODUCT_DICT_NAME from env vars, defaulting to {}", productDictName);

        if(systemProps.containsKey("RESOURCE_DIR")) {
            resourceDir = systemProps.get("RESOURCE_DIR");
            logger.info("Setting RESOURCE_DIR to {}", resourceDir);
        } else if (fileProps.containsKey("RESOURCE_DIR")) {
            resourceDir = fileProps.get("RESOURCE_DIR");
            logger.info("Setting RESOURCE_DIR to {}", resourceDir);
        } else logger.warn("Could not fetch RESOURCE_DIR from env vars, defaulting to {}", resourceDir);

        if(systemProps.containsKey("DATA_DIR")) {
            dataDir = systemProps.get("DATA_DIR");
            logger.info("Setting DATA_DIR to {}", dataDir);
        } else if (fileProps.containsKey("DATA_DIR")) {
            dataDir = fileProps.get("DATA_DIR");
            logger.info("Setting DATA_DIR to {}", dataDir);
        } else logger.warn("Could not fetch DATA_DIR from env vars, defaulting to {}", dataDir);

        if(systemProps.containsKey("NLP_DIR")) {
            nlpDir = systemProps.get("NLP_DIR");
            logger.info("Setting NLP_DIR to {}", nlpDir);
        } else if (fileProps.containsKey("NLP_DIR")) {
            nlpDir = fileProps.get("NLP_DIR");
            logger.info("Setting NLP_DIR to {}", nlpDir);
        } else logger.warn("Could not fetch NLP_DIR from env vars, defaulting to {}", nlpDir);

        if(systemProps.containsKey("PRETTY_PRINT")) {
            prettyPrint = Boolean.parseBoolean(systemProps.get("PRETTY_PRINT"));
            logger.info("Setting PRETTY_PRINT to {}", prettyPrint);
        } else if (fileProps.containsKey("PRETTY_PRINT")) {
            prettyPrint = Boolean.parseBoolean(fileProps.get("PRETTY_PRINT"));
            logger.info("Setting PRETTY_PRINT to {}", prettyPrint);
        } else logger.warn("Could not fetch PRETTY_PRINT from env vars, defaulting to {}", prettyPrint);

        if(systemProps.containsKey("TEST_MODE")) {
            testMode = Boolean.parseBoolean(systemProps.get("TEST_MODE"));
            logger.info("Setting TEST_MODE to {}", testMode);
        } else if (fileProps.containsKey("TEST_MODE")) {
            testMode = Boolean.parseBoolean(fileProps.get("TEST_MODE"));
            logger.info("Setting TEST_MODE to {}", testMode);
        } else logger.warn("Could not fetch TEST_MODE from env vars, defaulting to {}", testMode);

        if(systemProps.containsKey("REFRESH_INTERVAL")) {
            refreshInterval = Float.parseFloat(systemProps.get("REFRESH_INTERVAL"));
            logger.info("Setting REFRESH_INTERVAL to {} days", refreshInterval);
        } else if (fileProps.containsKey("REFRESH_INTERVAL")) {
            refreshInterval = Float.parseFloat(fileProps.get("REFRESH_INTERVAL"));
            logger.info("Setting REFRESH_INTERVAL to {} days", refreshInterval);
        } else logger.warn("Could not fetch REFRESH_INTERVAL from env vars, defaulting to {} days", refreshInterval);

        if(systemProps.containsKey("FULL_PULL_INTERVAL")) {
            fullPullInterval = Float.parseFloat(systemProps.get("FULL_PULL_INTERVAL"));
            logger.info("Setting FULL_PULL_INTERVAL to {} days", fullPullInterval);
        } else if (fileProps.containsKey("FULL_PULL_INTERVAL")) {
            fullPullInterval = Float.parseFloat(fileProps.get("FULL_PULL_INTERVAL"));
            logger.info("Setting FULL_PULL_INTERVAL to {} days", fullPullInterval);
        } else logger.warn("Could not fetch FULL_PULL_INTERVAL from env vars, defaulting to {} days", fullPullInterval);

        fetchHikariEnvVars(systemProps, fileProps);
        fetchRabbitEnvVars(systemProps, fileProps);
        fetchModelEnvVars(systemProps, fileProps);
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

        if(systemProps.containsKey("PNE_INPUT_QUEUE")) {
            rabbitInputQueue = systemProps.get("PNE_INPUT_QUEUE");
            logger.info("Setting PNE_INPUT_QUEUE to {}", rabbitInputQueue);
        } else if (fileProps.containsKey("PNE_INPUT_QUEUE")) {
            rabbitInputQueue = fileProps.get("PNE_INPUT_QUEUE");
            logger.info("Setting PNE_INPUT_QUEUE to {}", rabbitInputQueue);
        } else logger.warn("Could not fetch PNE_INPUT_QUEUE from env vars, defaulting to {}", rabbitInputQueue);

        if(systemProps.containsKey("PNE_OUTPUT_QUEUE")) {
            rabbitOutputQueue = systemProps.get("PNE_OUTPUT_QUEUE");
            logger.info("Setting PNE_OUTPUT_QUEUE to {}", rabbitOutputQueue);
        } else if (fileProps.containsKey("PNE_OUTPUT_QUEUE")) {
            rabbitOutputQueue = fileProps.get("PNE_OUTPUT_QUEUE");
            logger.info("Setting PNE_OUTPUT_QUEUE to {}", rabbitOutputQueue);
        } else logger.warn("Could not fetch PNE_OUTPUT_QUEUE from env vars, defaulting to {}", rabbitOutputQueue);

    }

    /**
     * Initialize model env vars
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchModelEnvVars(Map<String, String> systemProps, Map<String, String> fileProps){

        if(systemProps.containsKey("PRODUCT_DETECTOR_MODEL")) {
            productDetectorModel = systemProps.get("PRODUCT_DETECTOR_MODEL");
            logger.info("SETTING PRODUCT_DETECTOR_MODEL to {}", productDetectorModel);
        } else if (fileProps.containsKey("PRODUCT_DETECTOR_MODEL")) {
            productDetectorModel = fileProps.get("PRODUCT_DETECTOR_MODEL");
            logger.info("Setting PRODUCT_DETECTOR_MODEL to {}", productDetectorModel);
        } else logger.warn("Could not fetch PRODUCT_DETECTOR_MODEL from env vars, defaulting to {}", productDetectorModel);

        if(systemProps.containsKey("CHAR_2_VEC_CONFIG")) {
            char2VecConfig = systemProps.get("CHAR_2_VEC_CONFIG");
            logger.info("SETTING CHAR_2_VEC_CONFIG to {}", char2VecConfig);
        } else if (fileProps.containsKey("CHAR_2_VEC_CONFIG")) {
            char2VecConfig = fileProps.get("CHAR_2_VEC_CONFIG");
            logger.info("Setting CHAR_2_VEC_CONFIG to {}", char2VecConfig);
        } else logger.warn("Could not fetch CHAR_2_VEC_CONFIG from env vars, defaulting to {}", char2VecConfig);

        if(systemProps.containsKey("CHAR_2_VEC_WEIGHTS")) {
            char2VecWeights = systemProps.get("CHAR_2_VEC_WEIGHTS");
            logger.info("SETTING CHAR_2_VEC_WEIGHTS to {}", char2VecWeights);
        } else if (fileProps.containsKey("CHAR_2_VEC_WEIGHTS")) {
            char2VecWeights = fileProps.get("CHAR_2_VEC_WEIGHTS");
            logger.info("Setting CHAR_2_VEC_WEIGHTS to {}", char2VecWeights);
        } else logger.warn("Could not fetch CHAR_2_VEC_WEIGHTS from env vars, defaulting to {}", char2VecWeights);

        if(systemProps.containsKey("WORD_2_VEC")) {
            word2Vec = systemProps.get("WORD_2_VEC");
            logger.info("SETTING WORD_2_VEC to {}", word2Vec);
        } else if (fileProps.containsKey("WORD_2_VEC")) {
            word2Vec = fileProps.get("WORD_2_VEC");
            logger.info("Setting WORD_2_VEC to {}", word2Vec);
        } else logger.warn("Could not fetch WORD_2_VEC from env vars, defaulting to {}", word2Vec);

        if(systemProps.containsKey("NER_MODEL")) {
            nerModel = systemProps.get("NER_MODEL");
            logger.info("SETTING NER_MODEL to {}", nerModel);
        } else if (fileProps.containsKey("NER_MODEL")) {
            nerModel = fileProps.get("NER_MODEL");
            logger.info("Setting NER_MODEL to {}", nerModel);
        } else logger.warn("Could not fetch NER_MODEL from env vars, defaulting to {}", nerModel);

        if(systemProps.containsKey("NER_MODEL_NORMALIZER")) {
            nerModelNormalizer = systemProps.get("NER_MODEL_NORMALIZER");
            logger.info("SETTING NER_MODEL_NORMALIZER to {}", nerModelNormalizer);
        } else if (fileProps.containsKey("NER_MODEL_NORMALIZER")) {
            nerModelNormalizer = fileProps.get("NER_MODEL_NORMALIZER");
            logger.info("Setting NER_MODEL_NORMALIZER to {}", nerModelNormalizer);
        } else logger.warn("Could not fetch NER_MODEL_NORMALIZER from env vars, defaulting to {}", nerModelNormalizer);

        if(systemProps.containsKey("SENTENCE_MODEL")) {
            sentenceModel = systemProps.get("SENTENCE_MODEL");
            logger.info("SETTING SENTENCE_MODEL to {}", sentenceModel);
        } else if (fileProps.containsKey("SENTENCE_MODEL")) {
            sentenceModel = fileProps.get("SENTENCE_MODEL");
            logger.info("Setting SENTENCE_MODEL to {}", sentenceModel);
        } else logger.warn("Could not fetch SENTENCE_MODEL from env vars, defaulting to {}", sentenceModel);

    }
}
