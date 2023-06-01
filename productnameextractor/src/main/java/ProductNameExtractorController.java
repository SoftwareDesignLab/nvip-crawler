import model.*;
import db.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ProductNameExtractorController {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorController.class);
    private static final DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

    public static void main(String[] args) {
        logger.info("Pulling existing CVEs from the database...");
        final long getCVEStart = System.currentTimeMillis();

        // Fetch vulnerability data from the DB
        final Map<String, CompositeVulnerability> vulnMap = databaseHelper.getExistingCompositeVulnerabilities(100);

        // Extract vuln list and cast Vulnerability to CompositeVulnerability for the AffectedProductIdentifier
        final List<CompositeVulnerability> vulnerabilities = new ArrayList<>(vulnMap.values());

        logger.info("Successfully pulled {} existing CVEs from the database in {} seconds", vulnerabilities.size(), Math.floor(((double) (System.currentTimeMillis() - getCVEStart) / 1000) * 100) / 100);

        // Run the AffectedProductIdentifier with the fetched vuln list
        // This method will find Common Platform Enumerations (CPEs) and store them in the DB
        logger.info("Initializing and starting the AffectedProductIdentifier...");
        final long getProdStart = System.currentTimeMillis();
        final AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(vulnerabilities);
        final int count = affectedProductIdentifier.identifyAffectedReleases();
        logger.info("AffectedProductIdentifier found {} affected products in {} seconds", count, Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);
    }
}
