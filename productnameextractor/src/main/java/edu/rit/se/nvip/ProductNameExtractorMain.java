package edu.rit.se.nvip;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import com.opencsv.CSVReader;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.model.cpe.AffectedProduct;
import edu.rit.se.nvip.model.cpe.CpeGroup;
import edu.rit.se.nvip.model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Main class and driver for the NVIP Product Name Extractor.
 *
 * Core functionality is to determine which vulnerabilities will be processed, use the
 * AffectedProductIdentifier to derive affected products from those vulnerabilities,
 * and then insert those affected products into the database.
 *
 * By default, the ProductNameExtractor will wait idly for jobs to process from the NVIP Reconciler
 * via RabbitMQ. Once these jobs are finished and inserted into the database, the CVE list of all
 * the CVEs which affected products were mapped to will be passed to the NVIP Patchfinder.
 *
 * Also has a test mode (see environment variable TEST_MODE) to perform a quick run-through and ensure everything
 * is working correctly. This requires a 'test_vulnerabilities.csv' file be stored in the data directory.
 *
 * @author Paul Vickers
 * @author Dylan Mulligan
 *
 */

public class ProductNameExtractorMain {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorMain.class);
    public static final String currentDir = System.getProperty("user.dir");

    // Input Mode Variables (determine which CVEs to process - RabbitMQ jobs or manually created CVEs for Test Mode)
    private static final int rabbitPollInterval = ProductNameExtractorEnvVars.getRabbitPollInterval();
    private static final boolean testMode = ProductNameExtractorEnvVars.isTestMode();

    // Database Variables
    private static final String databaseType = ProductNameExtractorEnvVars.getDatabaseType();
    private static final String hikariUrl = ProductNameExtractorEnvVars.getHikariUrl();
    private static final String hikariUser = ProductNameExtractorEnvVars.getHikariUser();
    private static final String hikariPassword = ProductNameExtractorEnvVars.getHikariPassword();

    // Path Variables
    private static final String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
    private static final String dataDir = ProductNameExtractorEnvVars.getDataDir();
    private static final String nlpDir = ProductNameExtractorEnvVars.getNlpDir();

    // Variables for AffectedProductIdentifier
    private static final int numThreads = ProductNameExtractorEnvVars.getNumThreads();
    private static AffectedProductIdentifier affectedProductIdentifier;
    private static Map<String, CpeGroup> productDict;

    /**
     * Initialize the AffectedProductIdentifier & related AI models.
     * If already loaded in memory, just initializes the new vulnerability list to be processed.
     *
     * @param vulnList List of vulnerabilities to be processed
     */
    protected static void initializeProductIdentifier(List<CompositeVulnerability> vulnList){

        // If null, AffectedProductIdentifier needs to be initialized with AI models & product dictionary
        if(affectedProductIdentifier == null){
            logger.info("Initializing the AffectedProductIdentifier...");
            affectedProductIdentifier = new AffectedProductIdentifier(numThreads, vulnList);
            affectedProductIdentifier.initializeProductDetector(resourceDir, nlpDir, dataDir);

            productDict = ProductDictionary.getProductDict();
            affectedProductIdentifier.loadProductDict(productDict);

        // AffectedProductIdentifier already initialized, just need to change the vulnerabilities to be processed
        }else{
            logger.info("AffectedProductIdentifier already initialized!");
            affectedProductIdentifier.setVulnList(vulnList);
        }
    }

    /**
     * Releases the Affected Product Identifier and all of its models
     * as well as the product dictionary from memory. Forces garbage collection.
     */
    protected static void releaseResources(){
        if(affectedProductIdentifier != null){
            affectedProductIdentifier.releaseResources();
            affectedProductIdentifier = null;
        }

        if(productDict != null){
            ProductDictionary.unloadProductDict();
            productDict = null;
        }

        logger.info("All resources have been released!\n\n");
        System.gc();
    }

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
     * Determines which vulnerabilities to process within the Product Name Extractor
     * whether that be via RabbitMQ job pipeline or test mode and extracts affected products
     * from them, inserting those into the database. Then sends jobs to the NVIP Patchfinder.
     *
     * By default, the program will wait idly until jobs are received from the NVIP Reconciler
     * or a 'TERMINATE' message is received which will close the program.
     *
     * @param args (unused) program arguments
     *
     */
    public static void main(String[] args) {
        logger.info("CURRENT PATH --> " + currentDir);

        // Initialize Database Helper and Product Dictionary
        DatabaseHelper databaseHelper = new DatabaseHelper(databaseType, hikariUrl, hikariUser, hikariPassword);
        ProductDictionary.initializeProductDict();

        List<CompositeVulnerability> vulnList;
        final Messenger rabbitMQ = new Messenger();

        if(testMode){

            // If in test mode, create manual vulnerability list
            logger.info("Test mode enabled, creating test vulnerability list...");
            vulnList = createTestVulnList();

            initializeProductIdentifier(vulnList);

            // Process vulnerabilities
            final long getProdStart = System.currentTimeMillis();
            int numAffectedProducts = affectedProductIdentifier.identifyAffectedProducts().size();

            logger.info("Product Name Extractor found {} affected products in the test run in {} seconds", numAffectedProducts, Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);

            logger.info("Printing test results...");
            writeTestResults(vulnList);

        }else{
            // Otherwise using RabbitMQ, get the list of cve IDs from the reconciler and create vuln list from those
            while(true) {
                try {

                    // Get CVE IDs to be processed from reconciler
                    List<String> cveIds = rabbitMQ.waitForReconcilerMessage(rabbitPollInterval);

                    // If 'TERMINATE' message sent, initiate shutdown sequence and exit process
                    if (cveIds.size() == 1 && cveIds.get(0).equals("TERMINATE")) {
                        logger.info("TERMINATE message received from the Reconciler, shutting down...");
                        databaseHelper.shutdown();
                        System.exit(1);

                    // If 'FINISHED' message sent, jobs are done for now, release resources
                    } else if (cveIds.size() == 1 && cveIds.get(0).equals("FINISHED")) {
                        logger.info("FINISHED message received from the Reconciler, releasing resources...");
                        releaseResources();

                    // Otherwise, CVE jobs were received, process them
                    } else {
                        logger.info("Received job with CVE(s) {}", cveIds);

                        // Pull specific cve information from database for each CVE ID passed from reconciler
                        vulnList = databaseHelper.getSpecificCompositeVulnerabilities(cveIds);

                        // Initialize the affectedProductIdentifier and get ready to process cveIds
                        initializeProductIdentifier(vulnList);

                        // Identify affected products from the CVEs
                        final long getProdStart = System.currentTimeMillis();
                        List<AffectedProduct> affectedProducts = affectedProductIdentifier.identifyAffectedProducts();

                        // Insert the affected products found into the database
                        databaseHelper.insertAffectedProductsToDB(affectedProducts);
                        logger.info("Product Name Extractor found and inserted {} affected products to the database in {} seconds", affectedProducts.size(), Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);

                        // Clear cveIds, extract only the cveIds for which affected products were found to be sent to the Patchfinder
                        cveIds.clear();
                        for(AffectedProduct affectedProduct: affectedProducts){
                            if(!cveIds.contains(affectedProduct.getCveId())) cveIds.add(affectedProduct.getCveId());
                        }

                        // Send list of cveIds to Patchfinder
                        logger.info("Sending jobs to patchfinder...");
                        rabbitMQ.sendPatchFinderMessage(cveIds);
                        logger.info("Jobs have been sent!\n\n");
                    }

                } catch (Exception e) {
                    logger.error("Failed to get jobs from RabbitMQ, exiting program with error: {}", e.toString());
                    databaseHelper.shutdown();
                    System.exit(1);
                }
            }
        }
    }
}
