package edu.rit.se.nvip.utils;

import edu.rit.se.nvip.ReconcilerMain;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class ReconcilerEnvVars extends Properties {

    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);

    public static String hikariURL;
    public static  String hikariUser;
    public static  String hikariPassword;
    public static  List<String> filterList;
    public static  String reconcilerType;
    public static  List<String> processorList;
    public static  String knownSources;
    public static  String openAIKey;
    public static  String nvipDataDir;
    public static  String trainingDataDir;
    public static  String trainingData;
    public static  int characterizationLimit;
    public static  String characterizationApproach;
    public static  String characterizationMethod;
    public static  String dbType;
    public static  String dataDir;
    // call all the System.getEnvs() and store them in the correct datatypes in  fields
    public static void loadEnvVars() {
        // set default values if one isn't declared

        if (System.getenv("HIKARI_URL") == null){
            loadEnvList();
            return;
        }
        hikariURL = System.getenv("HIKARI_URL");
        hikariUser = System.getenv("HIKARI_USER");
        hikariPassword = System.getenv("HIKARI_PASSWORD");
        filterList = getListFromString(System.getenv("FILTER_LIST"));
        reconcilerType = System.getenv("RECONCILER_TYPE");
        processorList = getListFromString(System.getenv("PROCESSOR_LIST"));
        knownSources = System.getenv("KNOWN_SOURCES");
        openAIKey = System.getenv("OPENAI_KEY");
        nvipDataDir = System.getenv("NVIP_DATA_DIR");
        trainingDataDir = System.getenv("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR");
        trainingData = System.getenv("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA");
        characterizationLimit = Integer.parseInt(System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT"));
        characterizationApproach = System.getenv("NVIP_CHARACTERIZATION_APPROACH");
        characterizationMethod = System.getenv("NVIP_CHARACTERIZATION_METHOD");
        dbType = System.getenv("DB_TYPE");
        dataDir = System.getenv("DATA_DIR");

    }

    // in case we don't have environment variables actually set in the system, load them in directly from the env.list file instead
    public static void loadEnvList() {
        String filePath = System.getProperty("user.dir") + "\\env.list";

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int lastIndex = line.indexOf("=");
                if(line.equals("")){
                    lastIndex = 0;
                }
                String envVar = line.substring(line.indexOf("=") + 1);
                String envName = line.substring(0, lastIndex);

                switch (envName) {
                    case "HIKARI_URL":
                        hikariURL = addEnvvarString("hikariURL", envVar, "mysql://host.docker.internal:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true");
                        break;
                    case "HIKARI_USER":
                        hikariUser = addEnvvarString("hikariUser", envVar, "root");
                        break;
                    case "HIKARI_PASSWORD":
                        hikariPassword = addEnvvarString("hikariPassword", envVar, "root");;
                        break;
                    case "FILTER_LIST":
                        filterList = addEnvvarListString("filterList", getListFromString(envVar), "SIMPLE");
                        break;
                    case "RECONCILER_TYPE":
                        reconcilerType = addEnvvarString("reconcilerType", envVar, "SIMPLE");;
                        break;
                    case "PROCESSOR_LIST":
                        processorList = addEnvvarListString("processorList", getListFromString(envVar), "SIMPLE");
                        break;
                    case "KNOWN_SOURCES":
                        knownSources = addEnvvarString("knownSources", envVar, "packetstorm,tenable,oval.cisecurity,exploit-db,securityfocus,kb.cert,securitytracker,talosintelligence,gentoo,vmware,bugzilla,seclists,anquanke");;
                        break;
                    case "OPENAI_KEY":
                        openAIKey = addEnvvarString("openAIKey", envVar, "sk-xxxxxxxxxxxxx");;
                        break;
                    case "NVIP_DATA_DIR":
                        nvipDataDir = addEnvvarString("nvipDataDir", envVar, "src/main/java/edu/rit/se/nvip");;
                        break;
                    case "NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR":
                        trainingDataDir = addEnvvarString("trainingDataDir", envVar, "characterization/");;
                        break;
                    case "NVIP_CVE_CHARACTERIZATION_TRAINING_DATA":
                        trainingData = addEnvvarString("trainingData", envVar, "AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv");;
                        break;
                    case "NVIP_CVE_CHARACTERIZATION_LIMIT":
                        characterizationLimit = addEnvvarInt("characterizationLimit", Integer.parseInt(envVar), 5000);;
                        break;
                    case "NVIP_CHARACTERIZATION_APPROACH":
                        characterizationApproach = addEnvvarString("characterizationApproach", envVar, "ML");;
                        break;
                    case "NVIP_CHARACTERIZATION_METHOD":
                        characterizationMethod = addEnvvarString("characterizationMethod", envVar, "Vote");;
                        break;
                    case "DB_TYPE":
                        dbType = addEnvvarString("dbType", envVar, "mysql");;
                        break;
                    case "DATA_DIR":
                        dataDir = addEnvvarString("dataDir", envVar, "nvip_data");;
                        break;
                }
            }


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //GETTERS FOR EACH ENV VAR
    public static  String getHikariURL() {
        return hikariURL;
    }

    public static  String getHikariUser() {
        return hikariUser;
    }

    public static  String getHikariPassword() {
        return hikariPassword;
    }

    public static  List<String> getFilterList() {
        return filterList;
    }

    public static  String getReconcilerType() {
        return reconcilerType;
    }

    public static  List<String> getProcessorList() {
        return processorList;
    }

    public static  String getKnownSources() {
        return knownSources;
    }

    public static  String getOpenAIKey() {
        return openAIKey;
    }

    public static  String getNvipDataDir() {
        return nvipDataDir;
    }

    public static  String getTrainingDataDir() {
        return trainingDataDir;
    }

    public static  String getTrainingData() {
        return trainingData;
    }

    public static int getCharacterizationLimit() {
        return characterizationLimit;
    }

    public static  String getCharacterizationApproach() {
        return characterizationApproach;
    }

    public static  String getCharacterizationMethod() {
        return characterizationMethod;
    }

    public static  String getDbType() {
        return dbType;
    }

    public static  String getDataDir() {
        return dataDir;
    }

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
