package edu.rit.se.nvip.utils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class ReconcilerEnvVars extends Properties {
    private  String hikariURL;
    private  String hikariUser;
    private  String hikariPassword;
    private  String filterList;
    private  String reconcilerType;
    private  String processorList;
    private  String knownSources;
    private  String openAIKey;
    private  String nvipDataDir;
    private  String trainingDataDir;
    private  String trainingData;
    private  String characterizationLimit;
    private  String characterizationApproach;
    private  String characterizationMethod;
    private  String dbType;
    private  String dataDir;

    public ReconcilerEnvVars(){
        loadEnvVars();
    }
    // call all the System.getEnvs() and store them in the correct datatypes in  fields
    public void loadEnvVars() {
        // set default values if one isn't declared

        if (System.getenv("HIKARI_URL") == null){
            loadEnvList();
            return;
        }
        hikariURL = System.getenv("HIKARI_URL");
        hikariUser = System.getenv("HIKARI_USER");
        hikariPassword = System.getenv("HIKARI_PASSWORD");
        filterList = System.getenv("FILTER_LIST");
        reconcilerType = System.getenv("RECONCILER_TYPE");
        processorList = System.getenv("PROCESSOR_LIST");
        knownSources = System.getenv("KNOWN_SOURCES");
        openAIKey = System.getenv("OPENAI_KEY");
        nvipDataDir = System.getenv("NVIP_DATA_DIR");
        trainingDataDir = System.getenv("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR");
        trainingData = System.getenv("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA");
        characterizationLimit = System.getenv("NVIP_CVE_CHARACTERIZATION_LIMIT");
        characterizationApproach = System.getenv("NVIP_CHARACTERIZATION_APPROACH");
        characterizationMethod = System.getenv("NVIP_CHARACTERIZATION_METHOD");
        dbType = System.getenv("DB_TYPE");
        dataDir = System.getenv("DATA_DIR");

    }

    // in case we don't have environment variables actually set in the system, load them in directly from the env.list file instead
    public void loadEnvList() {
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
                        hikariURL = envVar;
                        break;
                    case "HIKARI_USER":
                        hikariUser = envVar;
                        break;
                    case "HIKARI_PASSWORD":
                        hikariPassword = envVar;
                        break;
                    case "FILTER_LIST":
                        filterList = envVar;
                        break;
                    case "RECONCILER_TYPE":
                        reconcilerType = envVar;
                        break;
                    case "PROCESSOR_LIST":
                        processorList = envVar;
                        break;
                    case "KNOWN_SOURCES":
                        knownSources = envVar;
                        break;
                    case "OPENAI_KEY":
                        openAIKey = envVar;
                        break;
                    case "NVIP_DATA_DIR":
                        nvipDataDir = envVar;
                        break;
                    case "NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR":
                        trainingDataDir = envVar;
                        break;
                    case "NVIP_CVE_CHARACTERIZATION_TRAINING_DATA":
                        trainingData = envVar;
                        break;
                    case "NVIP_CVE_CHARACTERIZATION_LIMIT":
                        characterizationLimit = envVar;
                        break;
                    case "NVIP_CHARACTERIZATION_APPROACH":
                        characterizationApproach = envVar;
                        break;
                    case "NVIP_CHARACTERIZATION_METHOD":
                        characterizationMethod = envVar;
                        break;
                    case "DB_TYPE":
                        dbType = envVar;
                        break;
                    case "DATA_DIR":
                        dataDir = envVar;
                        break;
                }
            }


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //GETTERS FOR EACH ENV VAR
    public  String getHikariURL() {
        return hikariURL;
    }

    public  String getHikariUser() {
        return hikariUser;
    }

    public  String getHikariPassword() {
        return hikariPassword;
    }

    public  String getFilterList() {
        return filterList;
    }

    public  String getReconcilerType() {
        return reconcilerType;
    }

    public  String getProcessorList() {
        return processorList;
    }

    public  String getKnownSources() {
        return knownSources;
    }

    public  String getOpenAIKey() {
        return openAIKey;
    }

    public  String getNvipDataDir() {
        return nvipDataDir;
    }

    public  String getTrainingDataDir() {
        return trainingDataDir;
    }

    public  String getTrainingData() {
        return trainingData;
    }

    public String getCharacterizationLimit() {
        return characterizationLimit;
    }

    public  String getCharacterizationApproach() {
        return characterizationApproach;
    }

    public  String getCharacterizationMethod() {
        return characterizationMethod;
    }

    public  String getDbType() {
        return dbType;
    }

    public  String getDataDir() {
        return dataDir;
    }
}
