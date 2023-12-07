/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

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
    DO_CHARACTERIZATION("DO_CHARACTERIZATION"),
    RABBIT_HOST("RABBIT_HOST"),
    RABBIT_VHOST("RABBIT_VHOST"),
    RABBIT_PORT("RABBIT_PORT"),
    RABBIT_USERNAME("RABBIT_USERNAME"),
    RABBIT_PASSWORD("RABBIT_PASSWORD"),
    RECONCILER_INPUT_QUEUE("RECONCILER_INPUT_QUEUE"),
    RECONCILER_OUTPUT_QUEUE("RECONCILER_OUTPUT_QUEUE"),
    MITRE_GITHUB_URL("MITRE_GITHUB_URL"),
    NVD_API_URL("NVD_API_URL"),
    SSVC_API_BASE_URL("SSVC_API_BASE_URL"),
    SSVC_API_PORT("SSVC_API_PORT"),
    SSVC_API_URI("SSVC_API_URI");


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
