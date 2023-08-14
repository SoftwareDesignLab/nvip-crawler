package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Timestamp;
import java.util.*;

public class ReconcilerMain {
    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);

    public static final Map<String, Object> envVars = new HashMap<>();
    private static final DatabaseHelper dbh = DatabaseHelper.getInstance();

    public static void main(String[] args) throws Exception {
        if (!DatabaseHelper.getInstance().testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }
        ReconcilerEnvVars.loadVars();
        ReconcilerController rc = new ReconcilerController();
        switch(ReconcilerEnvVars.getInputMode()){
            case "db":
                logger.info("Using Database for acquiring jobs");
                Set<String> jobs = dbh.getJobs();
                if (jobs == null){
                    logger.error("No Jobs found in database");
                    System.exit(0);
                }
                rc.main(jobs);
                break;
            case "rabbit":
                logger.info("Using Rabbit for acquiring jobs");
                Messenger messenger = new Messenger();
                while (true) {
                    List<String> jobsList = messenger.waitForCrawlerMessage(ReconcilerEnvVars.getRabbitTimeout());
                    if (jobsList == null) {
                        logger.info("Timeout reached with no jobs from rabbit");
                        break;
                    }
                    rc.main(new HashSet<>(jobsList));
                    // if we've set a rabbit timeout then we're implicitly only running once - should replace this with a new envvar
                    if (ReconcilerEnvVars.getRabbitTimeout() >= 0) {
                        break;
                    }
                }
        }

    }
}
