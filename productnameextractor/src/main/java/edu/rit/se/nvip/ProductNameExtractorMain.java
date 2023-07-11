package edu.rit.se.nvip;

import com.opencsv.CSVReader;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.model.cpe.AffectedProduct;
import edu.rit.se.nvip.model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ProductNameExtractorMain {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorController.class);
    public static final String currentDir = System.getProperty("user.dir");

    // Input Mode Variables (determine which CVEs to process)
    private static final int rabbitPollInterval = ProductNameExtractorEnvVars.getRabbitPollInterval();
    private static final boolean testMode = ProductNameExtractorEnvVars.isTestMode();
    private static List<String> cveIds;

    // Database Variables
    private static final String databaseType = ProductNameExtractorEnvVars.getDatabaseType();
    private static final String hikariUrl = ProductNameExtractorEnvVars.getHikariUrl();
    private static final String hikariUser = ProductNameExtractorEnvVars.getHikariUser();
    private static final String hikariPassword = ProductNameExtractorEnvVars.getHikariPassword();

    // Path Variables
    private static final String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
    private static final String dataDir = ProductNameExtractorEnvVars.getDataDir();


    /**
     * Method to generate a test vulnerability list of 6 CVEs to be run through the product name extractor.
     * Relies on/assumes that test_vulnerabilities.csv has already been created with sample CVEs and can be read.
     *
     * @return vulnList - list of vulnerabilities
     */
    private static ArrayList<CompositeVulnerability> createTestVulnList(){
        ArrayList<CompositeVulnerability> vulnList = new ArrayList<>();
        File testVulnerabilitiesFile = new File(resourceDir + "/" + dataDir + "/" + "test_vulnerabilities.csv");
        try{
            CSVReader reader = new CSVReader(new FileReader(testVulnerabilitiesFile));
            for(String[] line : reader.readAll()){
                CompositeVulnerability vulnerability = new CompositeVulnerability(
                        Integer.parseInt(line[0]),
                        line[1],
                        line[2],
                        CompositeVulnerability.CveReconcileStatus.UPDATE
                );

                vulnList.add(vulnerability);
            }
            reader.close();
        }catch(FileNotFoundException e){
            logger.warn("Could not find the test csv file at path {}", testVulnerabilitiesFile.getAbsolutePath());
            logger.warn("Please ensure that your working directory is correct. Current working directory: {}", currentDir);
        }catch(Exception e){
            logger.warn("Error {} reading the test csv file", e.toString());
        }

        return vulnList;
    }

    /**
     * Method to print the test run results to both console output and a specific results file.
     *
     * @param vulnList list of vulnerabilities
     */
    private static void writeTestResults(List<CompositeVulnerability> vulnList){
        File testResultsFile = new File(resourceDir + "/" + dataDir + "/" + "test_results.txt");
        try {
            PrintWriter writer = new PrintWriter(testResultsFile);
            // Go through each vulnerability and write it and its affected products to output and the file
            for (CompositeVulnerability vulnerability : vulnList) {
                if (vulnerability.getCveReconcileStatus() == CompositeVulnerability.CveReconcileStatus.DO_NOT_CHANGE)
                    continue; // skip the ones that are not changed!
                List<AffectedProduct> affectedProducts = new ArrayList<>(vulnerability.getAffectedProducts());

                StringBuilder builder = new StringBuilder();
                builder.append(vulnerability.getVulnID()).append("\t\t\t").append(vulnerability.getCveId()).append("\t\t\t")
                        .append(vulnerability.getDescription()).append("\n");
                builder.append("\n");

                for(AffectedProduct affectedProduct : affectedProducts){
                    builder.append(affectedProduct.getCpe()).append("\t\t\t").append(affectedProduct.getPURL())
                            .append("\t\t\t").append(affectedProduct.getSWID()).append("\n");
                }

                builder.append("\n\n\n");
                System.out.println("\n" + builder);
                writer.write(builder.toString());
            }
            writer.close();

            logger.info("Test results have been written to file {}", testResultsFile.getAbsolutePath());

        } catch(FileNotFoundException e){
            logger.warn("Could not find the test results file at path {}", testResultsFile.getAbsolutePath());
            logger.warn("Please ensure that your working directory is correct. Current working directory: {}", currentDir);
        }catch(Exception e){
            logger.warn("Error {} writing the test results file", e.toString());
        }

    }

    /**
     * Main method for the Product Name Extractor
     *
     * Determines which vulnerabilities to process within the Product Name Extractor and handles RabbitMQ pipeline.
     * Then starts the ProductNameExtractorController with said vulnerabilities to process.
     * Finally takes in the found affected products and inserts them into the database, notifying PatchFinder with jobs.
     *
     * @param args (unused) program arguments
     *
     * TODO: Make sure that resources are released at some point
     */
    public static void main(String[] args) {
        logger.info("CURRENT PATH --> " + currentDir);

        DatabaseHelper databaseHelper = new DatabaseHelper(databaseType, hikariUrl, hikariUser, hikariPassword);

        List<CompositeVulnerability> vulnList;
        final Messenger rabbitMQ = new Messenger();

        if(testMode){
            // If in test mode, create manual vulnerability list
            logger.info("Test mode enabled, creating test vulnerability list...");
            vulnList = createTestVulnList();

            final long getProdStart = System.currentTimeMillis();
            ProductNameExtractorController.initializeAffectedProductIdentifier();
            int numAffectedProducts = ProductNameExtractorController.run(vulnList).size();

            logger.info("Product Name Extractor found {} affected products in the test run in {} seconds", numAffectedProducts, Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);

            logger.info("Printing test results...");
            writeTestResults(vulnList);

        }else{
            // Otherwise using rabbitmq, get the list of cve IDs from the reconciler and create vuln list from those
            logger.info("Waiting for jobs from Reconciler...");
            while(true) {
                try {

                    // Get CVE IDs to be processed from reconciler
                    cveIds = rabbitMQ.waitForReconcilerMessage(rabbitPollInterval);

                    ProductNameExtractorController.initializeAffectedProductIdentifier();

                    // If no IDs pulled, break
                    if (cveIds == null) break;

                    // Pull specific cve information from database for each CVE ID passed from reconciler
                    vulnList = databaseHelper.getSpecificCompositeVulnerabilities(cveIds);

                    final long getProdStart = System.currentTimeMillis();
                    List<AffectedProduct> affectedProducts = ProductNameExtractorController.run(vulnList);

                    int numAffectedProducts = databaseHelper.insertAffectedProductsToDB(affectedProducts);
                    logger.info("Product Name Extractor found and inserted {} affected products to the database in {} seconds", numAffectedProducts, Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);

                    // Send list of cveIds to Patchfinder
                    logger.info("Sending jobs to patchfinder...");
                    rabbitMQ.sendPatchFinderMessage(cveIds);
                    rabbitMQ.sendPatchFinderFinishMessage();
                    logger.info("Jobs have been sent!");

                } catch (Exception e) {
                    logger.error("Failed to get jobs from RabbitMQ, exiting program...");
                    databaseHelper.shutdown();
                    System.exit(1);
                }
            }

        }
    }
}
