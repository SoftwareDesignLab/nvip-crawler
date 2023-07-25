package edu.rit.se.nvip;

import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class ReconcilerMain {
    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);

    public static final Map<String, Object> envVars = new HashMap<>();
    private static final DatabaseHelper dbh = DatabaseHelper.getInstance();
    private static Set<String> jobs;

    public static void main(String[] args) throws Exception {
        if (!DatabaseHelper.getInstance().testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }
        ReconcilerEnvVars.loadVars();
        switch(ReconcilerEnvVars.getInputMode()){
            case "db":
                logger.info("Using Database for acquiring jobs");
                jobs = dbh.getJobs();
                if (jobs == null){
                    logger.error("No Jobs found in database");
                    System.exit(0);
                }
                break;
            case "rabbit":
                logger.info("Using Rabbit for acquiring jobs");
                Messenger messenger = new Messenger();
                List<String> jobsList = messenger.waitForCrawlerMessage(ReconcilerEnvVars.getRabbitTimeout());
                if (jobsList == null){
                    logger.error("No Jobs found in rabbit");
                    System.exit(0);
                }
                jobs = new HashSet<>(jobsList);

                break;
        }
        ReconcilerController rc = new ReconcilerController();
        rc.main(jobs);

    }
}
