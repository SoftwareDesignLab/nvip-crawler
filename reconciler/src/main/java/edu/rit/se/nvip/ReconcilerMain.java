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
        // todo switch based on envvar INPUT_MODE to determine whether to use the database ("db") or rabbitmq ("rabbit")
        // todo wait around for up to envvar RABBIT_TIMEOUT for a rabbit message if the INPUT_MODE says to
        ReconcilerController rc = new ReconcilerController();
        rc.main(null); //todo give it jobs, either from the crawler or from dbh.getJobs()
    }
}
