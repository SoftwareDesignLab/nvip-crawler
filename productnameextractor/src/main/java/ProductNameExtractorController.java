import com.fasterxml.jackson.databind.ObjectMapper;
import db.*;
import model.cpe.CpeEntry;
import model.cpe.CpeGroup;
import model.cpe.Product;
import model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

/**
 * Controller for the isolated ProductNameExtractor package.
 *
 * @author Dylan Mulligan
 */
public class ProductNameExtractorController {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorController.class);
    private static final DatabaseHelper databaseHelper = DatabaseHelper.getInstance();
    private static final ObjectMapper OM = new ObjectMapper();
    private static int cveLimit = 300;
    private static int maxPages = 5;
    private static int maxAttemptsPerPage = 2;
    private static String productDictPath = "src/main/resources/data/product_dict.json";

    /**
     * Reads in the CPE dictionary from file at the given path.
     *
     * @param productDictPath path to read from
     * @return parsed CPE dictionary
     * @throws IOException if an exception occurs while parsing the CPE dictionary from file
     */
    public static Map<String, CpeGroup> readProductDict(String productDictPath) throws IOException {
        // Read in data
        final LinkedHashMap<String, LinkedHashMap> rawProductDict = OM.readValue(Paths.get(productDictPath).toFile(), LinkedHashMap.class);

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
    private static void fetchEnvVars() {
        // Fetch ENV_VARS and set all found configurable properties
        final Map<String, String> props = System.getenv();

        try {
            if(props.containsKey("CVE_LIMIT")) {
                cveLimit = Integer.parseInt(System.getenv("CVE_LIMIT"));
                logger.info("Setting CVE_LIMIT to {}", cveLimit);
            } else throw new Exception();
        } catch (Exception ignored) { logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to {}", cveLimit); }

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

        if(props.containsKey("PRODUCT_DICT_PATH")) {
            productDictPath = System.getenv("PRODUCT_DICT_PATH");
            logger.info("Setting PRODUCT_DICT_PATH to {}", productDictPath);
        } else logger.warn("Could not fetch PRODUCT_DICT_PATH from env vars, defaulting to {}", productDictPath);
    }

    /**
     * Main driver for the ProductNameExtractor, responsible for pulling vulnerabilities from the db,
     * loading the CPE dictionary, and cross-referencing that information to generate and store
     * entries in the affectedproducts table.
     *
     * @param args (unused) program arguments
     */
    public static void main(String[] args) {
        // Fetch values for required environment variables
        ProductNameExtractorController.fetchEnvVars();

        logger.info("Pulling existing CVEs from the database...");
        final long getCVEStart = System.currentTimeMillis();

        // Fetch vulnerability data from the DB
        final Map<String, CompositeVulnerability> vulnMap = databaseHelper.getExistingCompositeVulnerabilities(0);

        // Extract vuln list for the AffectedProductIdentifier
        final List<CompositeVulnerability> vulnerabilities = new ArrayList<>(vulnMap.values());

        logger.info("Successfully pulled {} existing CVEs from the database in {} seconds", vulnerabilities.size(), Math.floor(((double) (System.currentTimeMillis() - getCVEStart) / 1000) * 100) / 100);

        // This method will find Common Platform Enumerations (CPEs) and store them in the DB
        logger.info("Initializing and starting the AffectedProductIdentifier...");
        final long getProdStart = System.currentTimeMillis();

        // Init AffectedProductIdentifier
        final AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(vulnerabilities);

        // Init CPE dict data storage
        Map<String, CpeGroup> productDict;

        try {
            // Read in product dict
            productDict = readProductDict(productDictPath);

            // Load CPE dict
            affectedProductIdentifier.loadCPEDict(productDict);
        } catch (Exception e) {
            logger.error("Failed to load product dict at filepath '{}', querying NVD...: {}", productDictPath, e.toString());
            productDict = affectedProductIdentifier.loadCPEDict(maxPages, maxAttemptsPerPage);

            // Write CPE dict to file
            try {
                OM.writerWithDefaultPrettyPrinter().writeValue(new File(productDictPath), productDict);
            } catch (IOException ioe) {
                logger.error("Error writing product dict to filepath '{}': {}", productDictPath, ioe.toString());
            }
        }

        // Run the AffectedProductIdentifier with the fetched vuln list
        final Map<String, Product> productMap = affectedProductIdentifier.identifyAffectedReleases(cveLimit);

        databaseHelper.insertAffectedProductsToDB(vulnerabilities, productMap);

        logger.info("AffectedProductIdentifier found {} affected products in {} seconds", productMap.size(), Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);
    }
}