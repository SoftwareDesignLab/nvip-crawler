package edu.rit.se.nvip;

import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class ReconcilerMain {
    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);

    public static final Map<String, Object> envVars = new HashMap<>();
    private static DatabaseHelper dbh;
    private static ReconcilerController rc = new ReconcilerController();
    private Messenger messenger = new Messenger();

    public static void main(String[] args) throws Exception {
        ReconcilerMain main = new ReconcilerMain();
        main.createDatabaseInstance();
        main.main();
    }
    public void createDatabaseInstance(){
         dbh = DatabaseHelper.getInstance();
    }
    public void main() {
        rc.initialize();
        if (!dbh.testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }
        ReconcilerEnvVars.loadVars();
        switch(ReconcilerEnvVars.getInputMode()){
            case "db":
                logger.info("Using Database for acquiring jobs");
                Set<String> jobs = dbh.getJobs();
                if (jobs == null){
                    logger.error("No Jobs found in database");
                    break;
                }
                rc.main(jobs);
                break;
            case "rabbit":
                logger.info("Using Rabbit for acquiring jobs");
                while (true) {
                    List<String> jobsList;
                    try {
                        jobsList = messenger.waitForCrawlerMessage(ReconcilerEnvVars.getRabbitTimeout());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    if (jobsList == null) {
                        logger.error("Timeout reached with no jobs from rabbit");
                        break;
                    }
                    rc.main(new HashSet<>(jobsList));
                    // if we've set a rabbit timeout then we're implicitly only running once - should replace this with a new envvar
                    if (ReconcilerEnvVars.getRabbitTimeout() >= 0) {
                        break;
                    }
                }
            case "dev":
                final Set<String> devJobs = new HashSet<>();
                devJobs.add("CVE-2023-2825");
                rc.main(devJobs);
        }

    }
    public void setController(ReconcilerController r){
        rc = r;
    }
    public void setDatabaseHelper(DatabaseHelper db){
        dbh = db;
    }
    public void setMessenger(Messenger m){
        messenger = m;
    }
}
