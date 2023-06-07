import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import model.*;
import db.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class ProductNameExtractorController {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorController.class);
    private static final DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

    public static void main(String[] args) {
        // Fetch ENV_VARS
        int cveLimit = 300;
        int maxPages = 5;
        int maxAttemptsPerPage = 2;
        final String productDictPath = "src/test/resources/product_dict.json";
        try {
            cveLimit = Integer.parseInt(System.getenv("CVE_LIMIT"));
            logger.info("Setting CVE_LIMIT to {}", cveLimit);
        }
        catch (NullPointerException | NumberFormatException e) { logger.warn("Could not fetch CVE_LIMIT from env vars, defaulting to {}", cveLimit); }
        try {
            maxPages = Integer.parseInt(System.getenv("MAX_PAGES"));
            logger.info("Setting MAX_PAGES to {}", maxPages);
        }
        catch (NullPointerException | NumberFormatException e) { logger.warn("Could not fetch MAX_PAGES from env vars, defaulting to {}", maxPages); }

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

        // Init ObjectMapper
        final ObjectMapper OM = new ObjectMapper();

        // Fetch the CPE dict from NVD's CPE API
        Map<String, CpeGroup> productDict;

        try {
            productDict = OM.readValue(Paths.get(productDictPath).toFile(), Map.class);
            affectedProductIdentifier.loadCPEDict(productDict);
        } catch (Exception e) {
            logger.error("Failed to load product dict at filepath '{}', querying NVD...: {}", productDictPath, e.toString());
            productDict = affectedProductIdentifier.loadCPEDict(maxPages, maxAttemptsPerPage);

            // Write CPE dict to file
            try {
                OM.writeValue(new File(productDictPath), productDict);
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