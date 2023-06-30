package edu.rit.se.nvip;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.cpe.CpeEntry;
import edu.rit.se.nvip.model.cpe.CpeGroup;
import edu.rit.se.nvip.model.cve.AffectedProduct;
import edu.rit.se.nvip.model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.opencsv.CSVReader;

import java.io.*;
import java.nio.file.Paths;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.List;

/**
 * Controller for the isolated ProductNameExtractor package.
 *
 * @author Dylan Mulligan
 */
public class ProductNameExtractorController {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorController.class);
    private static final ObjectMapper OM = new ObjectMapper();
    protected static int cveLimit = 300;
    protected static int numThreads = 12;
    protected static String databaseType = "mysql";
    protected static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    protected static String hikariUser = "root";
    protected static String hikariPassword = "root";
    protected static int maxPages = 10;
    protected static int maxAttemptsPerPage = 2;
    protected static boolean prettyPrint = false;
    protected static boolean testMode = false;
    protected static String productDictName = "product_dict.json";
    protected static String resourceDir = "productnameextractor/nvip_data";
    protected static String dataDir = "data";
    protected static String nlpDir = "nlp";
    private static Instant productDictLastCompilationDate;
    private static AffectedProductIdentifier affectedProductIdentifier;

    /**
     * Reads in the CPE dictionary from file at the given path.
     *
     * @param productDictPath path to read from
     * @return parsed CPE dictionary
     * @throws IOException if an exception occurs while parsing the CPE dictionary from file
     */
    public static Map<String, CpeGroup> readProductDict(String productDictPath) throws IOException {
        // Read in raw data
        final LinkedHashMap<String, ?> rawData = OM.readValue(Paths.get(productDictPath).toFile(), LinkedHashMap.class);

        // Extract raw product data
        final LinkedHashMap<String, LinkedHashMap> rawProductDict = (LinkedHashMap<String, LinkedHashMap>) rawData.get("products");

        // Extract compilation time from file, default to 2000 if fails
        try {
            productDictLastCompilationDate = Instant.parse((String) rawData.get("comptime"));
        } catch (DateTimeException e) {
            logger.error("Error parsing compilation date from dictionary: {}", e.toString());
            productDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
        }

        // Init CPE dict
        final LinkedHashMap<String, CpeGroup> productDict = new LinkedHashMap<>();

        // Process into CpeGroups/CpeEntries
        for (Map.Entry<String, LinkedHashMap> entry : rawProductDict.entrySet()) {
            final String key = entry.getKey();
            LinkedHashMap value = entry.getValue();

            final String vendor = (String) value.get("vendor");
            final String product = (String) value.get("product");
            final String commonTitle = (String) value.get("commonTitle");
            final LinkedHashMap<String, LinkedHashMap> rawVersions = (LinkedHashMap<String, LinkedHashMap>) value.get("versions");
            final HashMap<String, CpeEntry> versions = new HashMap<>();
            for (Map.Entry<String, LinkedHashMap> versionEntry : rawVersions.entrySet()) {
                final LinkedHashMap versionValue = versionEntry.getValue();
                final String title = (String) versionValue.get("title");
                final String version = (String) versionValue.get("version");
                final String update = (String) versionValue.get("update");
                final String cpeID = (String) versionValue.get("cpeID");
                final String platform = (String) versionValue.get("platform");
                versions.put(version, new CpeEntry(title, version, update, cpeID, platform));
            }

            // Create and insert CpeGroup into productDict
            productDict.put(key, new CpeGroup(vendor, product, commonTitle, versions));
        }

        // Return filled productDict
        return productDict;
    }

    /**
     * Attempts to get all required environment variables from System.getenv() safely, logging
     * any missing or incorrect variables.
     */
    protected static void fetchEnvVars() {
        // Fetch ENV_VARS and set all found configurable properties
        final Map<String, String> props = System.getenv();

        try {
            if(props.containsKey("CVE_LIMIT")) {
                cveLimit = Integer.parseInt(System.getenv("CVE_LIMIT"));
                logger.info("Setting CVE_LIMIT to {}", cveLimit);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to {}", cveLimit); }

        try {
            if(props.containsKey("NUM_THREADS")) {
                numThreads = Integer.parseInt(System.getenv("NUM_THREADS"));
                logger.info("Setting NUM_THREADS to {}", numThreads);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch NUM_THREADS from env vars, defaulting to {}", numThreads); }

        try {
            if(props.containsKey("MAX_PAGES")) {
                maxPages = Integer.parseInt(System.getenv("MAX_PAGES"));
                logger.info("Setting MAX_PAGES to {}", maxPages);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch MAX_PAGES from env vars, defaulting to {}", maxPages); }

        try {
            if(props.containsKey("MAX_ATTEMPTS_PER_PAGE")) {
                maxAttemptsPerPage = Integer.parseInt(System.getenv("MAX_ATTEMPTS_PER_PAGE"));
                logger.info("Setting MAX_ATTEMPTS_PER_PAGE to {}", maxAttemptsPerPage);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch MAX_ATTEMPTS_PER_PAGE from env vars, defaulting to {}", maxAttemptsPerPage); }

        if(props.containsKey("PRODUCT_DICT_NAME")) {
            productDictName = System.getenv("PRODUCT_DICT_NAME");
            logger.info("Setting PRODUCT_DICT_NAME to {}", productDictName);
        } else logger.warn("Could not fetch PRODUCT_DICT_NAME from env vars, defaulting to {}", productDictName);

        if(props.containsKey("RESOURCE_DIR")) {
            resourceDir = System.getenv("RESOURCE_DIR");
            logger.info("Setting RESOURCE_DIR to {}", resourceDir);
        } else logger.warn("Could not fetch RESOURCE_DIR from env vars, defaulting to {}", resourceDir);

        if(props.containsKey("DATA_DIR")) {
            dataDir = System.getenv("DATA_DIR");
            logger.info("Setting DATA_DIR to {}", dataDir);
        } else logger.warn("Could not fetch DATA_DIR from env vars, defaulting to {}", dataDir);

        if(props.containsKey("NLP_DIR")) {
            nlpDir = System.getenv("NLP_DIR");
            logger.info("Setting NLP_DIR to {}", nlpDir);
        } else logger.warn("Could not fetch NLP_DIR from env vars, defaulting to {}", nlpDir);

        if(props.containsKey("PRETTY_PRINT")) {
            prettyPrint = Boolean.parseBoolean(System.getenv("PRETTY_PRINT"));
            logger.info("Setting PRETTY_PRINT to {}", prettyPrint);
        } else logger.warn("Could not fetch PRETTY_PRINT from env vars, defaulting to {}", prettyPrint);

        if(props.containsKey("TEST_MODE")) {
            testMode = Boolean.parseBoolean(System.getenv("TEST_MODE"));
            logger.info("Setting TEST_MODE to {}", testMode);
        } else logger.warn("Could not fetch TEST_MODE from env vars, defaulting to {}", testMode);

        fetchHikariEnvVars(props);
    }

    /**
     * Initialize database env vars
     * @param props map of env vars
     */
    private static void fetchHikariEnvVars(Map<String, String> props) {
        try {
            if(props.containsKey("HIKARI_URL")) {
                hikariUrl = System.getenv("HIKARI_URL");
                logger.info("Setting HIKARI_URL to {}", hikariUrl);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch HIKARI_URL from env vars, defaulting to {}", hikariUrl); }

        try {
            if(props.containsKey("HIKARI_USER")) {
                hikariUser = System.getenv("HIKARI_USER");
                logger.info("Setting HIKARI_USER to {}", hikariUser);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch HIKARI_USER from env vars, defaulting to {}", hikariUser); }

        try {
            if(props.containsKey("HIKARI_PASSWORD")) {
                hikariPassword = System.getenv("HIKARI_PASSWORD");
                logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch HIKARI_PASSWORD from env vars, defaulting to {}", hikariPassword); }
    }

    public static void writeProductDict(Map<String, CpeGroup> productDict, String productDictPath) {
        // Build output data map
        Map data = new LinkedHashMap<>();
        data.put("comptime", Instant.now().toString());
        data.put("products", productDict);

        // Write data to file
        try {
            final ObjectWriter w = prettyPrint ? OM.writerWithDefaultPrettyPrinter() : OM.writer();
            w.writeValue(new File(productDictPath), data);
            logger.info("Successfully wrote {} products to product dict file at filepath '{}'", productDict.size(), productDictPath);
        } catch (IOException ioe) {
            logger.error("Error writing product dict to filepath '{}': {}", productDictPath, ioe.toString());
        }
    }

    private static void updateProductDict(Map<String, CpeGroup> productDict, long timeSinceLastComp, String productDictPath) {
        // Check if product dict is stale
        if(timeSinceLastComp / (60 * 60 * 24) > 0) { // 60sec/min * 60min/hr * 24hrs = 1 day
            logger.info("Product dictionary file is stale, fetching data from NVD to refresh it...");
            int insertedCounter = 0;
            int notChangedCounter = 0;
            int updatedCounter = 0;
            final Map<String, CpeGroup> updatedProductDict = affectedProductIdentifier.queryCPEDict(maxPages, maxAttemptsPerPage); // Query

            logger.info("Refreshing product dictionary...");
            for (Map.Entry<String, CpeGroup> e : updatedProductDict.entrySet()) {
                final CpeGroup oldValue = productDict.put(e.getKey(), e.getValue());
                if(oldValue == null) insertedCounter++;
                else if(oldValue.equals(e.getValue())) notChangedCounter++;
                else updatedCounter++;
            }

            logger.info("Successfully refreshed the product dictionary with {} inserted, {} updated, and {} unchanged entries",
                    insertedCounter,
                    updatedCounter,
                    notChangedCounter
            );

            writeProductDict(productDict, productDictPath); // Write updated product dict
        }
    }

    /**
     * Method to generate a test vulnerability list of 6 CVEs to be run through the product name extractor
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
        }catch(Exception e){
            logger.warn("Error {} reading the test csv file", e.toString());
        }

        return vulnList;
    }

    /**
     * This method prints the test run results to both console output and a specific results file
     *
     * @param vulnList list of vulnerabilities
     */
    private static void writeTestResults(List<CompositeVulnerability> vulnList){
        File testResultsFile = new File(resourceDir + "/" + dataDir + "/" + "test_results.csv");
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

                logger.info("Test results have been written to file {}", testResultsFile.getAbsolutePath());
            }

            writer.close();
        } catch(FileNotFoundException e){
            logger.warn("Could not find the test results csv file at path {}", testResultsFile.getAbsolutePath());
        }

    }

    /**
     * Main driver for the ProductNameExtractor, responsible for pulling vulnerabilities from the db,
     * loading the CPE dictionary, and cross-referencing that information to generate and store
     * entries in the affectedproducts table.
     *
     * @param args (unused) program arguments
     */
    public static void main(String[] args) {
        logger.info("CURRENT PATH --> " + System.getProperty("user.dir"));

        // Fetch values for required environment variables
        ProductNameExtractorController.fetchEnvVars();

        DatabaseHelper databaseHelper = new DatabaseHelper(databaseType, hikariUrl, hikariUser, hikariPassword);

        logger.info("Pulling existing CVEs from the database...");
        final long getCVEStart = System.currentTimeMillis();

        final List<CompositeVulnerability> vulnList;
        if(testMode){
            // If in test mode, create manual vulnerability list
            logger.info("Test mode enabled, creating test vulnerability list...");
            vulnList = createTestVulnList();
        }else{
            // Otherwise, fetch vulnerability data from the DB
            vulnList = databaseHelper.getExistingCompositeVulnerabilities(0);
            logger.info("Successfully pulled {} existing CVEs from the database in {} seconds", vulnList.size(), Math.floor(((double) (System.currentTimeMillis() - getCVEStart) / 1000) * 100) / 100);
        }

        // This method will find Common Platform Enumerations (CPEs) and store them in the DB
        logger.info("Initializing and starting the AffectedProductIdentifier...");
        final long getProdStart = System.currentTimeMillis();

        // Init AffectedProductIdentifier
        ProductNameExtractorController.affectedProductIdentifier = new AffectedProductIdentifier(vulnList, numThreads);

        // Init CPE dict data storage
        Map<String, CpeGroup> productDict;

        // Build product dict path String
        final String productDictPath = resourceDir + "/" + dataDir + "/" + productDictName;

        try {
            // Read in product dict
            productDict = readProductDict(productDictPath);

            // Calculate time since last compilation
            final long timeSinceLastComp = Duration.between(productDictLastCompilationDate, Instant.now()).getSeconds();
            logger.info("Successfully read {} products from file '{}' ({} hours old)",
                    productDict.size(),
                    productDictName,
                    timeSinceLastComp / 3600 // seconds -> hours
            );

            // Update dict as needed
            updateProductDict(productDict, timeSinceLastComp, productDictPath);

            // Load CPE dict into affectedProductIdentifier
            affectedProductIdentifier.loadCPEDict(productDict);
        } catch (Exception e) {
            logger.error("Failed to load product dict at filepath '{}', querying NVD...: {}", productDictPath, e);
            productDict = affectedProductIdentifier.queryCPEDict(maxPages, maxAttemptsPerPage); // Query
            affectedProductIdentifier.loadCPEDict(productDict); // Load into CpeLookup

            writeProductDict(productDict, productDictPath); // Write product dict
        }

        // Run the AffectedProductIdentifier with the cveLimit
        List<AffectedProduct> affectedProducts = affectedProductIdentifier.identifyAffectedProducts(resourceDir, nlpDir, dataDir, cveLimit);

        if(testMode){
            logger.info("Printing test results...");
            writeTestResults(vulnList);
        }else{
            int numAffectedProducts = databaseHelper.insertAffectedProductsToDB(affectedProducts);
            logger.info("AffectedProductIdentifier found and inserted {} affected products to the database in {} seconds", numAffectedProducts, Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);
        }

    }
}