package edu.rit.se.nvip.productnameextractor;

import edu.rit.se.nvip.NVIPMain;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ProductNameExtractorMain {
    private static final Logger logger = LogManager.getLogger(NVIPMain.class);
    private static final DatabaseHelper databaseHelper = DatabaseHelper.getInstance();

    public static void main(String[] args) {
        logger.info("Pulling existing CVEs from the database...");
        // Fetch vulnerability data from the DB
        final Map<String, Vulnerability> vulnMap = databaseHelper.getExistingVulnerabilities();

        // Extract vuln list and cast Vulnerability to CompositeVulnerability for the AffectedProductIdentifier
        final List<CompositeVulnerability> vulnerabilities = vulnMap.values().stream().map(e -> (CompositeVulnerability) e).collect(Collectors.toList());

        // Run the AffectedProductIdentifier with the fetched vuln list
        // This method will find Common Platform Enumerations (CPEs) and store them in the DB
        logger.info("Initializing and starting the AffectedProductIdentifier...");
        final AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(vulnerabilities);
        affectedProductIdentifier.start();
    }
}
