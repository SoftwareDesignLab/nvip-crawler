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
    private Messenger messenger;

    public static void main(String[] args) throws Exception {
        ReconcilerMain main = new ReconcilerMain();
        main.setMessenger(new Messenger());
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
                runRabbitMessenger();
            case "dev":
                final Set<String> devJobs = new HashSet<>();
                devJobs.add("CVE-2023-2825");
                rc.main(devJobs);
        }

    }

    private void runRabbitMessenger() {
        messenger.setReconcilerController(rc);
        messenger.run();
    }

    public void setController(ReconcilerController r){
        rc = r;
    }
    public void setDatabaseHelper(DatabaseHelper db){
        dbh = db;
    }
    public void setMessenger(Messenger messenger){
        this.messenger = messenger;
    }
}
