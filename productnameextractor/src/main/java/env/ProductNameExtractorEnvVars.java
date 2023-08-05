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

    // Automatically load env vars
    static{
        initializeEnvVars();
    }

    // Manually load env vars
    public static void initializeEnvVars() {
        logger.info("CURRENT PATH --> " + System.getProperty("user.dir"));
        logger.info("Initializing Environment Variables...");
        fetchEnvVars(loadEnvVarsFromFile(envVarPath));
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

    /**
     * Loads environment variables from env.list file into HashMap and returns it.
     * By default, assumes that your working directory is 'nvip-crawler/productnameextractor'.
     *
     * @return map of environment variables
     */
    private static Map<String, String> loadEnvVarsFromFile(String path){
        Map<String, String> props = new HashMap<>();

        try{
            FileReader fileReader = new FileReader(path);
            BufferedReader reader = new BufferedReader(fileReader);

            // Go through each line
            String line = reader.readLine();
            while(line != null){
                // If it contains an equals sign, is an environment variable
                if(line.contains("=")){
                    int index = line.indexOf('=');
                    // Add the env var and its value
                    props.put(line.substring(0, index), line.substring(index + 1));
                }

                line = reader.readLine();
            }

        } catch (FileNotFoundException e){
            logger.error("Environment variable file (env.list) not found. Please ensure your working directory is correct");
            logger.error("Current working directory: {}", System.getProperty("user.dir"));
        } catch (IOException e){
            logger.error("Reading from environment variable file failed with error {}", e.toString());
        }

        return props;

    }

    /**
     * Attempts to fetch all required environment variables from parameter props safely, logging any
     * missing or incorrect variables. Resorts to default values if props doesn't contain a certain env var.
     *
     * @param props map of environment variables
     */
    private static void fetchEnvVars(Map<String, String> props) {

        if(props.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(props.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {}", rabbitPollInterval);
        } else logger.warn("Could not fetch RABBIT_POLL_INTERVAL from env vars, defaulting to {}", rabbitPollInterval);

        if(props.containsKey("NUM_THREADS")) {
            numThreads = Integer.parseInt(props.get("NUM_THREADS"));
            logger.info("Setting NUM_THREADS to {}", numThreads);
        } else logger.warn("Could not fetch NUM_THREADS from env vars, defaulting to {}", numThreads);

        if(props.containsKey("MAX_ATTEMPTS_PER_PAGE")) {
            maxAttemptsPerPage = Integer.parseInt(props.get("MAX_ATTEMPTS_PER_PAGE"));
            logger.info("Setting MAX_ATTEMPTS_PER_PAGE to {}", maxAttemptsPerPage);
        } else logger.warn("Could not fetch MAX_ATTEMPTS_PER_PAGE from env vars, defaulting to {}", maxAttemptsPerPage);

        if(props.containsKey("PRODUCT_DICT_NAME")) {
            productDictName = props.get("PRODUCT_DICT_NAME");
            logger.info("Setting PRODUCT_DICT_NAME to {}", productDictName);
        } else logger.warn("Could not fetch PRODUCT_DICT_NAME from env vars, defaulting to {}", productDictName);

        if(props.containsKey("RESOURCE_DIR")) {
            resourceDir = props.get("RESOURCE_DIR");
            logger.info("Setting RESOURCE_DIR to {}", resourceDir);
        } else logger.warn("Could not fetch RESOURCE_DIR from env vars, defaulting to {}", resourceDir);

        if(props.containsKey("DATA_DIR")) {
            dataDir = props.get("DATA_DIR");
            logger.info("Setting DATA_DIR to {}", dataDir);
        } else logger.warn("Could not fetch DATA_DIR from env vars, defaulting to {}", dataDir);

        if(props.containsKey("NLP_DIR")) {
            nlpDir = props.get("NLP_DIR");
            logger.info("Setting NLP_DIR to {}", nlpDir);
        } else logger.warn("Could not fetch NLP_DIR from env vars, defaulting to {}", nlpDir);

        if(props.containsKey("PRETTY_PRINT")) {
            prettyPrint = Boolean.parseBoolean(props.get("PRETTY_PRINT"));
            logger.info("Setting PRETTY_PRINT to {}", prettyPrint);
        } else logger.warn("Could not fetch PRETTY_PRINT from env vars, defaulting to {}", prettyPrint);

        if(props.containsKey("TEST_MODE")) {
            testMode = Boolean.parseBoolean(props.get("TEST_MODE"));
            logger.info("Setting TEST_MODE to {}", testMode);
        } else logger.warn("Could not fetch TEST_MODE from env vars, defaulting to {}", testMode);

        if(props.containsKey("REFRESH_INTERVAL")) {
            refreshInterval = Float.parseFloat(props.get("REFRESH_INTERVAL"));
            logger.info("Setting REFRESH_INTERVAL to {}", refreshInterval);
        } else logger.warn("Could not fetch REFRESH_INTERVAL from env vars, defaulting to {}", refreshInterval);

        if(props.containsKey("FULL_PULL_INTERVAL")) {
            fullPullInterval = Float.parseFloat(props.get("FULL_PULL_INTERVAL"));
            logger.info("Setting FULL_PULL_INTERVAL to {}", fullPullInterval);
        } else logger.warn("Could not fetch FULL_PULL_INTERVAL from env vars, defaulting to {}", fullPullInterval);

        fetchHikariEnvVars(props);
        fetchRabbitEnvVars(props);
        fetchModelEnvVars(props);
    }

    /**
     * Initialize database env vars
     *
     * @param props map of env vars
     */
    private static void fetchHikariEnvVars(Map<String, String> props) {
        if(props.containsKey("DB_TYPE")) {
            databaseType = props.get("DB_TYPE");
            logger.info("Setting DB_TYPE to {}", databaseType);
        } else logger.warn("Could not fetch DB_TYPE from env vars, defaulting to {}", databaseType);

        if(props.containsKey("HIKARI_URL")) {
            hikariUrl = props.get("HIKARI_URL");
            logger.info("Setting HIKARI_URL to {}", hikariUrl);
        } else logger.warn("Could not fetch HIKARI_URL from env vars, defaulting to {}", hikariUrl);

        if(props.containsKey("HIKARI_USER")) {
            hikariUser = props.get("HIKARI_USER");
            logger.info("Setting HIKARI_USER to {}", hikariUser);
        } else logger.warn("Could not fetch HIKARI_USER from env vars, defaulting to {}", hikariUser);

        if(props.containsKey("HIKARI_PASSWORD")) {
            hikariPassword = props.get("HIKARI_PASSWORD");
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
            rabbitHost = props.get("RABBIT_HOST");
            logger.info("Setting RABBIT_HOST to {}", rabbitHost);
        } else logger.warn("Could not fetch RABBIT_HOST from env vars, defaulting to {}", rabbitHost);

        if(props.containsKey("RABBIT_USERNAME")) {
            rabbitUsername = props.get("RABBIT_USERNAME");
            logger.info("Setting RABBIT_USERNAME to {}", rabbitUsername);
        } else logger.warn("Could not fetch RABBIT_USERNAME from env vars, defaulting to {}", rabbitUsername);

        if(props.containsKey("RABBIT_PASSWORD")) {
            rabbitPassword = props.get("RABBIT_PASSWORD");
            logger.info("Setting RABBIT_PASSWORD to {}", rabbitPassword);
        } else logger.warn("Could not fetch RABBIT_PASSWORD from env vars, defaulting to {}", rabbitPassword);
    }

    /**
     * Initialize model env vars
     *
     * @param props map of env vars
     */
    private static void fetchModelEnvVars(Map<String, String> props){
        if(props.containsKey("PRODUCT_DETECTOR_MODEL")) {
            productDetectorModel = props.get("PRODUCT_DETECTOR_MODEL");
            logger.info("SETTING PRODUCT_DETECTOR_MODEL to {}", productDetectorModel);
        } else logger.warn("Could not fetch PRODUCT_DETECTOR_MODEL from env vars, defaulting to {}", productDetectorModel);

        if(props.containsKey("CHAR_2_VEC_CONFIG")) {
            char2VecConfig = props.get("CHAR_2_VEC_CONFIG");
            logger.info("SETTING CHAR_2_VEC_CONFIG to {}", char2VecConfig);
        } else logger.warn("Could not fetch CHAR_2_VEC_CONFIG from env vars, defaulting to {}", char2VecConfig);

        if(props.containsKey("CHAR_2_VEC_WEIGHTS")) {
            char2VecWeights = props.get("CHAR_2_VEC_WEIGHTS");
            logger.info("SETTING CHAR_2_VEC_WEIGHTS to {}", char2VecWeights);
        } else logger.warn("Could not fetch CHAR_2_VEC_WEIGHTS from env vars, defaulting to {}", char2VecWeights);

        if(props.containsKey("WORD_2_VEC")) {
            word2Vec = props.get("WORD_2_VEC");
            logger.info("SETTING WORD_2_VEC to {}", word2Vec);
        } else logger.warn("Could not fetch WORD_2_VEC from env vars, defaulting to {}", word2Vec);

        if(props.containsKey("NER_MODEL")) {
            nerModel = props.get("NER_MODEL");
            logger.info("SETTING NER_MODEL to {}", nerModel);
        } else logger.warn("Could not fetch NER_MODEL from env vars, defaulting to {}", nerModel);

        if(props.containsKey("NER_MODEL_NORMALIZER")) {
            nerModelNormalizer = props.get("NER_MODEL_NORMALIZER");
            logger.info("SETTING NER_MODEL_NORMALIZER to {}", nerModelNormalizer);
        } else logger.warn("Could not fetch NER_MODEL_NORMALIZER from env vars, defaulting to {}", nerModelNormalizer);

        if(props.containsKey("SENTENCE_MODEL")) {
            sentenceModel = props.get("SENTENCE_MODEL");
            logger.info("SETTING SENTENCE_MODEL to {}", sentenceModel);
        } else logger.warn("Could not fetch SENTENCE_MODEL from env vars, defaulting to {}", sentenceModel);

    }
}
