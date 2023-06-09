package edu.rit.se.nvip;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class ReconcilerMain {
    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);
    public static final Map<String, Object> envVars = new HashMap<>();

    public ReconcilerMain() {
        getEnvVars();

        if (!DatabaseHelper.getInstance().testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        ReconcilerMain rcm = new ReconcilerMain(); // just to instantiate envvars
        // reconcilers still have a Map<String, Integer> knownCveSources, but the old implementation always sets the int to 0.
        // I think the int is supposed to represent a notion of priority, but since the value is never referenced I will continue keeping them 0
        Map<String, Integer> sourceMap = new HashMap<>();

        for (String source : (List<String>) envVars.get("knownSources")) {
            sourceMap.put(source, 0);
        }

        ReconcilerController rc = new ReconcilerController(
                (List<String>) envVars.get("filterList"),
                (String) envVars.get("reconcilerType"),
                (List<String>) envVars.get("processorList"),
                sourceMap);
        rc.main();
    }

    private void getEnvVars() {
        String filterList = System.getenv("FILTER_LIST");
        String reconcilerType = System.getenv("RECONCILER_TYPE");
        String processorList = System.getenv("PROCESSOR_LIST");
        String knownSourceList = System.getenv("KNOWN_SOURCES"); // TODO this is legacy setup to match existing reconciler implementations, should be re-thought
        String openaiKey = System.getenv("OPENAI_KEY");


        addEnvvarListString("filterList", getListFromString(filterList), "SIMPLE",
                "WARNING: Filter List is not defined in FILTER_LIST, meaning only the SIMPLE filter will be used");
        addEnvvarString("reconcilerType", reconcilerType, "SIMPLE",
                "WARNING: Reconciler Type is not defined in RECONCILER_TYPE, using default type SIMPLE");
        addEnvvarListString("processorList", getListFromString(processorList), "SIMPLE",
                "WARNING: Processor List is not defined in PROCESSOR_LIST, meaning only the SIMPLE processor will be used");
        addEnvvarListString("knownSources", getListFromString(knownSourceList), "",
                "WARNING: Known Sources is not defined in KNOWN_SOURCES, meaning that no sources will have priority");
        addEnvvarString("openaiKey", openaiKey, "",
                "WARNING: OpenAi Key is not defined in OPENAI_KEY");
    }

    private void addEnvvarString(String name, String value, String defaultValue, String warning) {
        if (value != null && !value.isEmpty()) {
            envVars.put(name, value);
        }
        else {
            envVars.put(name, defaultValue);
            logger.warn(warning);
        }
    }

    private void addEnvvarListString(String name, List<String> value, String defaultValue, String warning) {
        if (value != null && value.size() > 0) {
            envVars.put(name, value);
        }
        else {
            List<String> list = new ArrayList<>();
            list.add(defaultValue);
            envVars.put(name, list);
        }
    }

    private List<String> getListFromString(String commaSeparatedList) {
        // Default to empty list on null value for commaSeparatedList
        if(commaSeparatedList == null) return new ArrayList<>();

        return Arrays.asList(commaSeparatedList.split(","));
    }
}
