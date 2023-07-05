package edu.rit.se.nvip.utils;

import java.util.Properties;

public class ReconcilerEnvVars extends Properties {
    private static String openAIKey;

    // call all the System.getEnvs() and store them in the correct datatypes in static fields
    public void loadEnvVars() {
        // System.getenv()
        // transform to right data type
        // set default values if one isn't declared
    }

    // in case we don't have environment variables actually set in the system, load them in directly from the env.list file instead
    public void loadEnvList() {
    }

    // have one of these for every envvar, don't make System.getenv() calls in any of them
    public String getOpenAIKey() {
        return openAIKey;
    }
}
