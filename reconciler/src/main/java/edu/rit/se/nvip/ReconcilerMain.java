/**
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
*/

package edu.rit.se.nvip;

import com.rabbitmq.client.ConnectionFactory;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.repositories.*;
import edu.rit.se.nvip.reconciler.filter.FilterHandler;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.sql.DataSource;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeoutException;


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

                DataSource ds = DatabaseHelper.getInstance().getDataSource();
                RawDescriptionRepository rawRepo = new RawDescriptionRepository(ds);
                VulnerabilityRepository vulnRepo = new VulnerabilityRepository(ds);
                CharacterizationRepository charRepo = new CharacterizationRepository(ds);
                NvdMitreRepository nmRepo = new NvdMitreRepository(ds);
                RunHistoryRepository rhRepo = new RunHistoryRepository(ds);

                NvdCveController nvdController = new NvdCveController();
                nvdController.createDatabaseInstance();

                MitreCveController mitreController = new MitreCveController();
                mitreController.setDatabaseHelper(nmRepo);
                mitreController.initializeController();


                ReconcilerController rc = new ReconcilerController(rawRepo, vulnRepo, charRepo, nmRepo, rhRepo, filterHandler, reconciler, nvdController, mitreController);

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
