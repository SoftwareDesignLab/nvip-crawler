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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import edu.rit.se.nvip.model.cpe.CpeEntry;
import edu.rit.se.nvip.model.cpe.CpeGroup;
import edu.rit.se.nvip.model.cpe.AffectedProduct;
import edu.rit.se.nvip.model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.awt.*;
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
    private static final int numThreads = ProductNameExtractorEnvVars.getNumThreads();
    private static final int maxPages = ProductNameExtractorEnvVars.getMaxPages();
    private static final int maxAttemptsPerPage = ProductNameExtractorEnvVars.getMaxAttemptsPerPage();
    private static final boolean prettyPrint = ProductNameExtractorEnvVars.isPrettyPrint();
    private static final String productDictName = ProductNameExtractorEnvVars.getProductDictName();
    private static final String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
    private static final String dataDir = ProductNameExtractorEnvVars.getDataDir();
    private static final String nlpDir = ProductNameExtractorEnvVars.getNlpDir();
    private static final String productDictPath = resourceDir + "/" + dataDir + "/" + productDictName;
    private static Instant productDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
    private static Instant productDictLastRefreshDate = Instant.parse("2000-01-01T00:00:00.00Z");
    private static AffectedProductIdentifier affectedProductIdentifier;
    private static Map<String, CpeGroup> productDict;

    /**
     * Initialize the AffectedProductIdentifier & related models
     * as well as load the product dictionary. If both have already been loaded,
     * controller is ready to process CVEs.
     */
    public static void initializeController(List<CompositeVulnerability> vulnList){
        if(affectedProductIdentifier == null){
            logger.info("Initializing the AffectedProductIdentifier...");
            affectedProductIdentifier = new AffectedProductIdentifier(numThreads, vulnList);
            affectedProductIdentifier.initializeProductDetector(resourceDir, nlpDir, dataDir);
        }else{
            logger.info("AffectedProductIdentifier already initialized!");
            affectedProductIdentifier.setVulnList(vulnList);
        }

        if(productDict == null){
            try{
                logger.info("Loading product dictionary...");
                productDict = readProductDict(productDictPath);
            } catch (IOException e){
                logger.error("Error loading product dictionary: {}", e.toString());
            }
        }else{
            logger.info("Product dictionary already loaded!");
        }
    }

    /**
     * Releases the Affected Product Identifier and all of its models
     * as well as the product dictionary from memory.
     */
    protected static void releaseResources(){
        if(affectedProductIdentifier != null){
            affectedProductIdentifier.releaseResources();
            affectedProductIdentifier = null;
            productDict = null;
        }
    }

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
            productDictLastCompilationDate = Instant.parse((String) rawData.get("compTime"));
            productDictLastRefreshDate = Instant.parse((String) rawData.get("refreshTime"));
        } catch (Exception e) {
            logger.error("Error parsing compilation/refresh date from dictionary: {}", e.toString());
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
     * Function to write the queried CPE dictionary data from NVD to a local json file which
     * will be read in future runs. Also stores most recent composition time (full re-pull of NVD data)
     * as well as refresh time (any time the file is changed).
     *
     * @param productDict data from NVD CPE Dictionary
     * @param productDictPath path to the newly created productdict.json file
     */
    public static void writeProductDict(Map<String, CpeGroup> productDict, String productDictPath) {
        // Build output data map
        Map data = new LinkedHashMap<>();

        // If just refreshing, old comp time is kept. Always update refresh time
        data.put("compTime", productDictLastCompilationDate.toString());
        data.put("refreshTime", Instant.now().toString());
        data.put("products", productDict);

        // Write data to file
        try {
            final ObjectWriter w = prettyPrint ? OM.writerWithDefaultPrettyPrinter() : OM.writer();
            w.writeValue(new File(productDictPath), data);
            logger.info("Successfully wrote {} products to product dict file at filepath '{}'", productDict.size(), productDictPath);
        } catch(Exception e){
            logger.error("Error writing product dict to filepath '{}': {}", productDictPath, e.toString());
            logger.warn("Please ensure that your working directory is correct. Current working directory: {}", ProductNameExtractorMain.currentDir);
        }
    }

    /**
     * Function to take in the current product dictionary data stored in the local productdict.json file
     * and update it with a fresh NVD CPE Dictionary data query. If the time since the last composition (full pull
     * of data) is greater than a week, the current data is wiped and a full re-pull from NVD is performed.
     *
     * On the other hand, if it has been less than a week since the most recent composition but longer than a day
     * since the most recent refresh, then var maxPages number of pages of NVD's dictionary are queried and the
     * current data is updated with the freshly pulled data, logging the changes.
     *
     * @param productDict
     * @param timeSinceLastComp
     * @param timeSinceLastRefresh
     * @param productDictPath
     */
    private static void updateProductDict(Map<String, CpeGroup> productDict, long timeSinceLastComp, long timeSinceLastRefresh, String productDictPath) {
        // Check if it has been over a week since a full pull/compilation of the NVD dictionary
        if(timeSinceLastComp / (60 * 60 * 24) > 7) { // 60sec/min * 60min/hr * 24hrs = 1 day
            logger.info("Product dictionary file is over a week old, fully querying NVD data with no page limit...");

            // Fully clear product dict and fill it with no page limit query
            int oldSize = productDict.size();
            productDict.clear();
            productDict.putAll(affectedProductIdentifier.queryCPEDict(0, maxAttemptsPerPage));

            // Update last comp date to now
            productDictLastCompilationDate = Instant.now();

            logger.info("Successfully pulled entire new dictionary with {} new entries, writing it...",
                    productDict.size() - oldSize);

            writeProductDict(productDict, productDictPath); // Write entire new product dict

        // If less than a week has gone by but over a day, refresh the product dictionary with a maxPages NVD query
        } else if (timeSinceLastRefresh / (60 * 60 * 24) > 0){
            logger.info("Product dictionary file is stale, fetching data from NVD to refresh it...");
            int insertedCounter = 0;
            int notChangedCounter = 0;
            int updatedCounter = 0;
            //TODO: Modify query method to query by recent entries for refresh
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

            writeProductDict(productDict, productDictPath); // Write new product dict
        }
    }

    /**
     * Main driver for the ProductNameExtractor, responsible for taking in vulnerabilities,
     * loading the CPE dictionary, and cross-referencing that information to generate and store
     * return affected products that have been found.
     *
     * @return affected products found
     */
    public static List<AffectedProduct> run() {
        try {

            // Calculate time since last compilation
            final long timeSinceLastComp = Duration.between(productDictLastCompilationDate, Instant.now()).getSeconds();
            final long timeSinceLastRefresh = Duration.between(productDictLastRefreshDate, Instant.now()).getSeconds();

            logger.info("Successfully read {} products from file '{}' ({} hour(s) old)",
                    productDict.size(),
                    productDictName,
                    timeSinceLastRefresh / 3600 // seconds -> hours
            );

            // Update dict as needed
            updateProductDict(productDict, timeSinceLastComp, timeSinceLastRefresh, productDictPath);

            // Load CPE dict into affectedProductIdentifier
            affectedProductIdentifier.loadCPEDict(productDict);
        } catch (Exception e) {
            logger.warn("Failed to load product dict at filepath '{}', querying NVD...: {}", productDictPath, e);
            productDict = affectedProductIdentifier.queryCPEDict(maxPages, maxAttemptsPerPage); // Query
            affectedProductIdentifier.loadCPEDict(productDict); // Load into CpeLookup
            productDictLastCompilationDate = Instant.now(); // Set last comp date to now
            productDictLastRefreshDate = Instant.now(); // Set last refresh date to now

            writeProductDict(productDict, productDictPath); // Write product dict
        }

        // Run the AffectedProductIdentifier and return the products found
        return affectedProductIdentifier.identifyAffectedProducts();

    }
}