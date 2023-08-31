package edu.rit.se.nvip.utils;

import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class ReconcilerEnvVars extends Properties {

    private static final Logger logger = LogManager.getLogger(ReconcilerEnvVars.class);
    private static final String DEFAULT_ENV_LIST_PATH = "env.list";
    private static final Map<String, String> rawEnvVars = new HashMap<>();
    private static String hikariURL;
    private static String hikariUser;
    private static String hikariPassword;
    private static String inputMode;
    private static int rabbitTimeout;
    private static List<String> filterList;
    private static String reconcilerType;
    private static List<String> knownSources;
    private static String openAIKey;
    private static String trainingDataDir;
    private static String trainingData;
    private static int characterizationLimit;
    private static String characterizationApproach;
    private static String characterizationMethod;
    private static String dataDir;
    private static int doCharacterization;
    private static String rabbitHost;
    private static String rabbitUsername;
    private static String rabbitPassword;
    private static String rabbitQueueIn;
    private static String rabbitQueueOut;
    private static String mitreGithubUrl;
    private static String nvdApiUrl;

    /**
     * Ensures vars are loaded before anybody else uses this class. They can be reloaded by calling any public load method manually
     */
    static {
        loadVars(DEFAULT_ENV_LIST_PATH);
    }
    public static void loadVars(String path) {
        String currentDirectory = System.getProperty("user.dir");
        logger.info("Current Directory: " + currentDirectory);
        if (System.getenv(EnvVar.FILTER_LIST.toString()) == null) {
            clearLoadParse(false, path);
        } else {
            clearLoadParse(true, "");
        }
    }
    public static void loadVars() {
        if (System.getenv(EnvVar.HIKARI_URL.toString()) == null) {
            clearLoadParse(false, DEFAULT_ENV_LIST_PATH);
        } else {
            clearLoadParse(true, "");
        }
    }
    public static void loadFromEnv(String path) {
        clearLoadParse(true, path);
    }
    public static void loadFromEnv() {
        clearLoadParse(true, DEFAULT_ENV_LIST_PATH);
    }

    public static void loadFromFile(String filePath) {
        clearLoadParse(false, filePath);
    }

    public static void loadFromFile() {
        loadFromFile(DEFAULT_ENV_LIST_PATH);
    }

    private static void clearLoadParse(boolean useEnv, String fPath) {
        rawEnvVars.clear();
        if (useEnv) {
            loadRawFromEnv();
        } else {
            loadRawFromFile(fPath);
        }
        parseAndSet();
    }

    private static void parseAndSet() {
        for (String envName : rawEnvVars.keySet()) {
            EnvVar ev = EnvVar.getEnvVarByName(envName);
            if (ev == null) {
                // something unexpected must have been in the env.list, ignore it
                continue;
            }
            String envVar = rawEnvVars.get(envName);
            switch (ev) {
                case HIKARI_URL:
                    hikariURL = addEnvvarString(envName, envVar, "mysql://host.docker.internal:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true");
                    break;
                case HIKARI_USER:
                    hikariUser = addEnvvarString(envName, envVar, "root");
                    break;
                case HIKARI_PASSWORD:
                    hikariPassword = addEnvvarString(envName, envVar, "root");
                    break;
                case INPUT_MODE:
                    inputMode = addEnvvarString(envName, envVar, "db");
                    break;
                case RABBIT_TIMEOUT:
                    rabbitTimeout = addEnvvarInt(envName, Integer.parseInt(envVar), 3600);
                    break;
                case FILTER_LIST:
                    filterList = addEnvvarListString(envName, getListFromString(envVar), "SIMPLE");
                    break;
                case RECONCILER_TYPE:
                    reconcilerType = addEnvvarString(envName, envVar, "SIMPLE");
                    break;
                case KNOWN_SOURCES:
                    knownSources = addEnvvarListString(envName, getListFromString(envVar), "packetstorm,tenable,oval.cisecurity,exploit-db,securityfocus,kb.cert,securitytracker,talosintelligence,gentoo,vmware,bugzilla,seclists,anquanke");
                    break;
                case OPENAI_KEY:
                    openAIKey = addEnvvarString(envName, envVar, "sk-xxxxxxxxxxxxx");
                    break;
                case NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR:
                    trainingDataDir = addEnvvarString(envName, envVar, "characterization");
                    break;
                case NVIP_CVE_CHARACTERIZATION_TRAINING_DATA:
                    trainingData = addEnvvarString(envName, envVar, "AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv");
                    break;
                case NVIP_CVE_CHARACTERIZATION_LIMIT:
                    characterizationLimit = addEnvvarInt(envName, Integer.parseInt(envVar), 5000);
                    break;
                case NVIP_CHARACTERIZATION_APPROACH:
                    characterizationApproach = addEnvvarString(envName, envVar, "ML");
                    break;
                case NVIP_CHARACTERIZATION_METHOD:
                    characterizationMethod = addEnvvarString(envName, envVar, "Vote");
                    break;
                case DATA_DIR:
                    dataDir = addEnvvarString(envName, envVar, "nvip_data");
                    break;
                case DO_CHARACTERIZATION:
                    doCharacterization = addEnvvarInt(envName, Integer.parseInt(envVar), 0);
                    break;
                case RABBIT_HOST:
                    rabbitHost = addEnvvarString(envName, envVar, "localhost");
                    break;
                case RABBIT_USERNAME:
                    rabbitUsername = addEnvvarString(envName, envVar, "guest");
                    break;
                case RABBIT_PASSWORD:
                    rabbitPassword = addEnvvarString(envName, envVar, "guest");
                    break;
                case RECONCILER_INPUT_QUEUE:
                    rabbitQueueIn = addEnvvarString(envName, envVar, "CRAWLER_OUT");
                    break;
                case RECONCILER_OUTPUT_QUEUE:
                    rabbitQueueOut = addEnvvarString(envName, envVar, "RECONCILER_OUT");
                    break;
                case MITRE_GITHUB_URL:
                    mitreGithubUrl = addEnvvarString(envName, envVar, "https://github.com/CVEProject/cvelist");
                    break;
                case NVD_API_URL:
                    nvdApiUrl = addEnvvarString(envName, envVar, "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>");
                    break;
            }
        }
    }

    private static void loadRawFromEnv() {
        for (EnvVar name : EnvVar.values()) {
            rawEnvVars.put(name.toString(), System.getenv(name.toString()));
        }

    }

    // in case we don't have environment variables actually set in the system, load them in directly from the env.list file instead
    private static void loadRawFromFile(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if(line.startsWith("#")) continue;

                int lastIndex = line.indexOf("=");
                if (line.equals("")) {
                    lastIndex = 0;
                }
                String envVar = line.substring(line.indexOf("=") + 1);
                String envName = line.substring(0, lastIndex);

                rawEnvVars.put(envName, envVar);
            }
            logger.info(
                    "Successfully read in {} environment variables from file @ '{}'",
                    rawEnvVars.size(),
                    System.getProperty("user.dir") + "\\" + filePath
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void setEnvListPath(String path){

    }

    //GETTERS FOR EACH ENV VAR
    public static String getHikariURL() {return hikariURL;}

    public static String getHikariUser() {
        return hikariUser;
    }

    public static String getHikariPassword() {
        return hikariPassword;
    }
    public static String getInputMode() {return inputMode;}

    public static int getRabbitTimeout() {return rabbitTimeout;}
    public static List<String> getFilterNameList() {
        return filterList;
    }

    public static List<Filter> getFilterList() {
        return filterList.stream().map(FilterFactory::createFilter).collect(Collectors.toList());
    }

    public static String getReconcilerType() {
        return reconcilerType;
    }

    public static List<String> getKnownSources() {
        return knownSources;
    }
    public static boolean getDoCharacterization() {return doCharacterization == 1;}
    /**
     * Legacy reconcilers use this one. It's unclear what the integer is supposed to be but in the old code it was always set to 0 so that's how I'm leaving it
     * @return
     */
    public static Map<String, Integer> getKnownSourceMap() {
        Map<String, Integer> out = new HashMap<>();
        for (String source : knownSources) {
            out.put(source, 0);
        }
        return out;
    }

    public static String getOpenAIKey() {
        return openAIKey;
    }

    public static String getTrainingDataDir() {
        return trainingDataDir;
    }

    public static String getTrainingData() {
        return trainingData;
    }

    public static int getCharacterizationLimit() {
        return characterizationLimit;
    }

    public static String getCharacterizationApproach() {
        return characterizationApproach;
    }

    public static String getCharacterizationMethod() {
        return characterizationMethod;
    }

    public static String getDataDir() {
        return dataDir;
    }
    public static String getRabbitHost() {
        return rabbitHost;
    }
    public static String getRabbitUsername() {
        return rabbitUsername;
    }
    public static String getRabbitPassword() {
        return rabbitPassword;
    }
    public static String getRabbitQueueOut() {return rabbitQueueOut;}
    public static String getRabbitQueueIn() {return rabbitQueueIn;}
    public static String getMitreGithubUrl() {return mitreGithubUrl;}
    public static String getNvdApiUrl() {return nvdApiUrl;}


    private static String addEnvvarString(String name, String value, String defaultValue) {
        if (value != null && !value.isEmpty()) {
            return value;
        }
        else {
            logger.warn("No environment variable set for {}, setting as default value", name);
            return defaultValue;
        }
    }

    private static int addEnvvarInt(String name, int value, int defaultValue) {
        if (value != 0) {
            return value;
        }
        else {
            logger.warn("No environment variable set for {}, setting as default value", name);
            return defaultValue;
        }
    }

    private static List<String> addEnvvarListString(String name, List<String> value, String defaultValue) {
        if (value != null && value.size() > 0) {
            return value;
        }
        else {
            logger.warn("No environment variable set for {}, setting as default value", name);
            return getListFromString(defaultValue);
        }
    }
    private static List<String> getListFromString(String commaSeparatedList) {
        // Default to empty list on null value for commaSeparatedList
        if(commaSeparatedList == null) return new ArrayList<>();

        return Arrays.asList(commaSeparatedList.split(","));
    }

}
