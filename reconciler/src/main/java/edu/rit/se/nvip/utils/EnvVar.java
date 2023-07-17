package edu.rit.se.nvip.utils;

import java.util.Arrays;

public enum EnvVar {
    HIKARI_URL("HIKARI_URL"),
    HIKARI_USER("HIKARI_USER"),
    HIKARI_PASSWORD("HIKARI_PASSWORD"),
    INPUT_MODE("INPUT_MODE"),
    RABBIT_TIMEOUT("RABBIT_TIMEOUT"),
    FILTER_LIST("FILTER_LIST"),
    RECONCILER_TYPE("RECONCILER_TYPE"),
    PROCESSOR_LIST("PROCESSOR_LIST"),
    KNOWN_SOURCES("KNOWN_SOURCES"),
    OPENAI_KEY("OPENAI_KEY"),
    NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR"),
    NVIP_CVE_CHARACTERIZATION_TRAINING_DATA("NVIP_CVE_CHARACTERIZATION_TRAINING_DATA"),
    NVIP_CVE_CHARACTERIZATION_LIMIT("NVIP_CVE_CHARACTERIZATION_LIMIT"),
    NVIP_CHARACTERIZATION_APPROACH("NVIP_CHARACTERIZATION_APPROACH"),
    NVIP_CHARACTERIZATION_METHOD("NVIP_CHARACTERIZATION_METHOD"),
    DATA_DIR("DATA_DIR"),
    DO_CHARACTERIZATION("DO_CHARACTERIZATION");


    private final String name;
    EnvVar(String name) {
        this.name = name;
    }
    @Override
    public String toString() {
        return this.name;
    }

    public static EnvVar getEnvVarByName(String name) {
        return Arrays.stream(EnvVar.values()).filter(ev -> ev.name.equals(name)).findFirst().orElse(null);
    }
}
