package edu.rit.se.nvip;

import com.rabbitmq.client.ConnectionFactory;
import edu.rit.se.nvip.filter.FilterHandler;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;


public class ReconcilerMain {
    private static final Logger logger = LogManager.getLogger(ReconcilerMain.class);

    public static void main(String[] args) throws Exception {

        ReconcilerEnvVars.loadVars();
        switch(ReconcilerEnvVars.getInputMode()){
//            case "db":
//                logger.info("Using Database for acquiring jobs");
//                Set<String> jobs = dbh.getJobs();
//                if (jobs == null){
//                    logger.error("No Jobs found in database");
//                    break;
//                }
//
//                Set<CompositeVulnerability> reconciledVulns = rc.reconcileCves(jobs);
//                rc.characterizeCves(reconciledVulns);
//                rc.updateTimeGaps(reconciledVulns);
//                rc.createRunStats(reconciledVulns);
//                break;
            case "rabbit":
                logger.info("Using Rabbit for acquiring jobs");

                ConnectionFactory connectionFactory = new ConnectionFactory();
                connectionFactory.setHost(ReconcilerEnvVars.getRabbitHost());
                connectionFactory.setVirtualHost(ReconcilerEnvVars.getRabbitVHost());
                connectionFactory.setPort(ReconcilerEnvVars.getRabbitPort());
                connectionFactory.setUsername(ReconcilerEnvVars.getRabbitUsername());
                connectionFactory.setPassword(ReconcilerEnvVars.getRabbitPassword());

                try {
                    connectionFactory.useSslProtocol();
                } catch (NoSuchAlgorithmException e) {
                    logger.error(e.getMessage());
                    throw new RuntimeException(e);
                } catch (KeyManagementException e) {
                    logger.error(e.getMessage());
                    throw new RuntimeException(e);
                }

                String inputQueueName = ReconcilerEnvVars.getRabbitQueueIn();
                String outputQueueName = ReconcilerEnvVars.getRabbitQueueOut();

                FilterHandler filterHandler = new FilterHandler(ReconcilerEnvVars.getFilterList());
                Reconciler reconciler = ReconcilerFactory.createReconciler(ReconcilerEnvVars.getReconcilerType());
                reconciler.setKnownCveSources(ReconcilerEnvVars.getKnownSourceMap());

                NvdCveController nvdController = new NvdCveController();
                nvdController.createDatabaseInstance();

                MitreCveController mitreController = new MitreCveController();
                mitreController.initializeController();

                ReconcilerController rc = new ReconcilerController(DatabaseHelper.getInstance(), filterHandler, reconciler, nvdController, mitreController);

                Messenger messenger = new Messenger(connectionFactory, inputQueueName, outputQueueName, rc);
                messenger.run();
//            case "dev":
//                final Set<String> devJobs = new HashSet<>();
//                devJobs.add("CVE-2023-2825");
//
//                Set<CompositeVulnerability> reconciledCves = rc.reconcileCves(devJobs);
//                rc.characterizeCves(reconciledCves);
//                rc.updateTimeGaps(reconciledCves);
//                rc.createRunStats(reconciledCves);
        }
    }
}
