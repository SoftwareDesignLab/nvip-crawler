package edu.rit.se.nvip;

import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class ReconcilerMain {
    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);

    public static final Map<String, Object> envVars = new HashMap<>();

    public static void main(String[] args) {
        if (!DatabaseHelper.getInstance().testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }
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
}
