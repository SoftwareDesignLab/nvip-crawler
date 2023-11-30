package dictionary;

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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import edu.rit.se.nvip.db.model.CpeEntry;
import edu.rit.se.nvip.db.model.CpeGroup;
import env.ProductNameExtractorEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Product Dictionary Class
 *
 * Represents the CPE dictionary pulled from NVD with all necessary utility
 * to keep it up to date and functional throughout runs of the Product Name Extractor.
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */

public class ProductDictionary {
    private static final Logger logger = LogManager.getLogger(ProductDictionary.class);

     // Dictionary Reading/Storage Vars

    private static final ObjectMapper OM = new ObjectMapper();
    private static final String productDictName = ProductNameExtractorEnvVars.getProductDictName();
    private static final float refreshInterval = ProductNameExtractorEnvVars.getRefreshInterval();
    private static final float fullPullInterval = ProductNameExtractorEnvVars.getFullPullInterval();
    private static Map<String, CpeGroup> productDict;
    private static Instant productDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
    private static Instant productDictLastRefreshDate = Instant.parse("2000-01-01T00:00:00.00Z");

     // NVD Querying/Writing Vars

    private static final Pattern cpePattern = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");
    private static final String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36";
    private static final String baseNVDUrl = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    private static final int resultsPerPage = 10000; // Cannot query more than 10000 per page
    private static final int maxAttemptsPerPage = ProductNameExtractorEnvVars.getMaxAttemptsPerPage();

    // Getter for product dict
    public static Map<String, CpeGroup> getProductDict() {
        if(productDict == null){
            initializeProductDict();
        }
        return productDict;
    }

    /**
     * Unloads product dictionary from memory, resets the dates
     */
    public static void unloadProductDict(){
        logger.info("Releasing product dictionary from memory...");
        if(productDict != null){
            productDict = null;
            productDictLastCompilationDate = Instant.parse("2000-01-01T00:00:00.00Z");
            productDictLastRefreshDate = Instant.parse("2000-01-01T00:00:00.00Z");
        }
    }

    /**
     * Initializes the product dictionary.
     *
     * Attempts to read from stored product_dict.json file at productDictPath,
     * if it cannot be found then an entire new dictionary file is pulled from NVD & created.
     *
     * If it is found, then the time since last full pull/refresh is calculated and updateProductDict()
     * is called to see if it is necessary to either do a full pull or refresh the dict.
     */
    public static void initializeProductDict(){
        logger.info("Initializing Product Dictionary...");

        final String productDictPath = ProductNameExtractorEnvVars.getResourceDir() + "/"
                + ProductNameExtractorEnvVars.getDataDir() + "/"
                + productDictName;

        try{
            // Read in existing product dictionary
            productDict = readProductDict(productDictPath);

            // Calculate time since last compilation
            final long timeSinceLastFullPull = Duration.between(productDictLastCompilationDate, Instant.now()).getSeconds();
            final long timeSinceLastRefresh = Duration.between(productDictLastRefreshDate, Instant.now()).getSeconds();

            logger.info("Successfully read {} products from file '{}' ({} day(s) since refresh, {} day(s) since full query)",
                    productDict.size(),
                    productDictPath,
                    Math.floor((float) timeSinceLastRefresh / 3600 / 24 * 10) / 10, // seconds -> hours
                    Math.floor((float) timeSinceLastFullPull / 3600 / 24 * 10) / 10 // seconds -> hours
            );

            // Update dictionary as needed
            updateProductDict(productDict, timeSinceLastFullPull, timeSinceLastRefresh, productDictPath);

        } catch (Exception e) {
            // If error occurs reading current stored dictionary, perform a full query of NVD's CPE Dictionary
            logger.warn("Failed to load product dictionary at filepath '{}' due to error: {}", productDictPath, e);
            logger.warn("Please ensure your working directory is correct. Current working directory: {}", System.getProperty("user.dir"));
            logger.info("Fully querying NVD data with no page limit...");

            // Not refreshing, doing a full pull, pass in false
            productDict = queryProductDict(false);
            productDictLastCompilationDate = Instant.now();
            writeProductDict(productDict, productDictPath);
        }
    }

    /**
     * Reads in the CPE dictionary from file at the given path.
     *
     * @param productDictPath path to read dictionary from
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
            final ObjectWriter w = ProductNameExtractorEnvVars.isPrettyPrint() ? OM.writerWithDefaultPrettyPrinter() : OM.writer();
            w.writeValue(new File(productDictPath), data);
            logger.info("Successfully wrote {} products to product dict file at filepath '{}'", productDict.size(), productDictPath);
        } catch(Exception e){
            logger.error("Error writing product dict to filepath '{}': {}", productDictPath, e.toString());
            logger.warn("Please ensure that your working directory is correct. Current working directory: {}", System.getProperty("user.dir"));
        }
    }

    /**
     * Function to take in the current product dictionary data stored in the local productdict.json file
     * and update it with a fresh NVD CPE Dictionary data query. If the time since the last full pull
     * of data is greater than fullPullInterval (env var), the current data is wiped and a full re-pull from NVD is performed.
     *
     * On the other hand, if it has been less than fullPullInterval since the most recent full pull but longer than refreshInterval
     * (env var) since the most recent refresh, then only NVD's recently updated entries are queried and the
     * current data is updated with the freshly pulled data, logging the changes.
     *
     * @param productDict dictionary of CPEs
     * @param timeSinceLastFullPull time since last full pull of the dictionary
     * @param timeSinceLastRefresh time since last refresh of the dictionary
     * @param productDictPath path to product dictionary file
     */
    private static void updateProductDict(Map<String, CpeGroup> productDict, long timeSinceLastFullPull, long timeSinceLastRefresh, String productDictPath) {
        // Check if it has been over full pull interval time since a full pull/compilation of the NVD dictionary
        if((float) timeSinceLastFullPull / (60 * 60 * 24) > fullPullInterval) { // 60sec/min * 60min/hr * 24hrs = 1 day
            logger.info("Product dictionary file is over {} days old, fully querying NVD data with no page limit...", fullPullInterval);

            // Fully clear product dict and fill it with no page limit query
            int oldSize = productDict.size();
            productDict.clear();

            // Not refreshing, doing a full pull, pass in false
            productDict.putAll(queryProductDict(false));

            // Update last comp date to now
            productDictLastCompilationDate = Instant.now();

            logger.info("Successfully pulled entire new dictionary with {} new entries, writing it...",
                    productDict.size() - oldSize);

            writeProductDict(productDict, productDictPath); // Write entire new product dict

        // If less than full pull interval time has gone by but over refresh interval, refresh the product dictionary with new entries from NVD
        } else if ((float) timeSinceLastRefresh / (60 * 60 * 24) > refreshInterval){
            logger.info("Product dictionary file is over {} days old, querying data from NVD to refresh it...", refreshInterval);
            int insertedCounter = 0;
            int updatedCounter = 0;

            // Refreshing, pass in true and perform a query pulling only changed entries from the most recent refresh to now
            final Map<String, CpeGroup> updatedProductDict = queryProductDict(true);

            // Refresh old dict with new dict and count how many entries are inserted, updated, or unchanged
            logger.info("Refreshing product dictionary...");
            for (Map.Entry<String, CpeGroup> e : updatedProductDict.entrySet()) {
                final CpeGroup oldValue = productDict.put(e.getKey(), e.getValue());
                if(oldValue == null) insertedCounter++;
                else updatedCounter++;
            }

            logger.info("Successfully refreshed the product dictionary with {} inserted and {} updated entries",
                    insertedCounter,
                    updatedCounter
            );

            writeProductDict(productDict, productDictPath); // Write new product dict
        }
    }

    /**
     * Compiles a CPE dictionary of products from querying NVD's CPE API
     *
     * @param isRefresh whether we are refreshing or doing a full pull
     * @return a map of loaded CpeGroup objects
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Map<String, CpeGroup> queryProductDict(boolean isRefresh) {

        // Init cpeMapFile
        final HashMap<String, CpeGroup> productDict = new HashMap<>();

        // Collect CPE data from NVD API
        try {
            int index = 0;

            // Get raw data
            LinkedHashMap<String, ?> rawData;
            if(isRefresh) rawData = getNvdCpeData(index, true);
            else rawData = getNvdCpeData(index, false);

            // Extract results data
            int remainingResults = (int) rawData.get("totalResults");
            final int totalPages = (int) Math.ceil((double) remainingResults / resultsPerPage);

            while(remainingResults > 0) {
                try {
                    // Skip first query, as it was already done in order to get the totalResults number
                    if(index > 0) {
                        // Query next page
                        rawData = getNvdCpeData(index, isRefresh);
                    }

                    // Extract product data
                    final List<LinkedHashMap> rawProductData = (List<LinkedHashMap>) rawData.get("products");

                    rawProductData.forEach(p -> {
                        // Extract product map
                        final LinkedHashMap<String, LinkedHashMap> product = (LinkedHashMap<String, LinkedHashMap>) p.get("cpe");

                        // Extract cpe name
                        final String fullCpeName = String.valueOf(product.get("cpeName"));

                        // Extract cpe id
                        final String cpeId = String.valueOf(product.get("cpeNameId"));

                        // Match against CPE regex
                        final Matcher m = cpePattern.matcher(fullCpeName);

                        // Ensure CPE is formed correctly
                        if(!m.find() || m.group(1) == null || m.group(2) == null || m.group(3) == null) {
                            logger.warn("CPE '{}' skipped due to bad form", fullCpeName);
                            return;
                        }

                        // Store matcher values
                        final String vendorName = m.group(1);
                        final String productName = m.group(2);
                        final String version = m.group(3);

                        // Build key
                        final String key = String.join(":", vendorName, productName);

                        // If key is not found, create new group and entry
                        if(!productDict.containsKey(key)) {
                            // Create group
                            CpeGroup value = new CpeGroup(vendorName, productName);

                            // Create & add entry to group
                            value.addVersion(new CpeEntry(productName, version, cpeId));

                            // Add group to cpeMapFile
                            productDict.put(key, value);
                        }
                        // Update existing entries with versions
                        else {
                            // Get existing group from cpeMapFile
                            final CpeGroup existingValue = productDict.get(key);

                            // Get existing versions from group
                            final Set<String> existingVersions = existingValue.getVersions().keySet();

                            // If version does not already exist, add new entry
                            if(!existingVersions.contains(version)) {
                                // Create & add entry to group
                                existingValue.addVersion(new CpeEntry(productName, version, cpeId));
                            }
                        }
                    });

                    final int page = 1 + (index / resultsPerPage);

                    // Reduce remaining results by number parsed
                    remainingResults -= resultsPerPage;
                    // Increment index
                    index += resultsPerPage;
                    // Sleep 6 sec between queries (NVD Recommended)
                    Thread.sleep(6000);

                    logger.info("Successfully loaded CPE dictionary page {}/{}", page, totalPages);
                }

                // This block will skip the page if the content was unable to be pulled
                catch (IOException e) {
                    logger.info("Failed to load CPE dictionary page {}/{}, skipping...", 1 + (index / resultsPerPage), totalPages);

                    // Reduce remaining results by number parsed
                    remainingResults -= resultsPerPage;
                    // Increment index
                    index += resultsPerPage;
                    // Sleep 6 sec between queries (NVD Recommended)
                    Thread.sleep(6000);
                }
            }

            if(isRefresh){
                logger.info("In the new data, {} total results were merged into {} CPE groups to be added to the dictionary",
                        rawData.get("totalResults"), productDict.size());
            }

        } catch (Exception e) {
            logger.error("Error loading CPE dictionary: {}", e.toString());
        }

        return productDict;
    }

    /**
     * Queries NVD with the given startIndex parameter, returning the raw mapped data
     *
     * @param startIndex offset for query
     * @return raw mapped data
     * @throws JsonParseException if an exception occurs while attempting to parse the page contents
     * @throws IOException if an exception occurs while attempting to retrieve the page contents
     */
    @SuppressWarnings("unchecked")
    private static LinkedHashMap<String, ?> getNvdCpeData(int startIndex, boolean isRefresh) throws JsonParseException, IOException {

        final String url;

        // If refreshing, include lastModStartDate and lastModEndDate in the URL to only pull changes from most recent refresh til now
        if(isRefresh){
            String lastModStartDate = productDictLastRefreshDate.toString();
            String lastModEndDate = Instant.now().toString();
            url = baseNVDUrl + String.format("?resultsPerPage=%s&startIndex=%s&lastModStartDate=%s&lastModEndDate=%s",
                    resultsPerPage, startIndex, lastModStartDate, lastModEndDate);

        // Otherwise, querying the entire thing at specified index/results per page
        } else url = baseNVDUrl + String.format("?resultsPerPage=%s&startIndex=%s", resultsPerPage, startIndex);

        logger.info("Fetching product list from CPE dictionary page {} at {}", 1 + startIndex / resultsPerPage, url);


        // Parse contents (if fails, will throw JsonParseException)
        try {
            // Query URL for contents (THIS WILL THROW AN InterruptedIOException WHEN IT HITS A 403 RESPONSE)
            final String contents = getContentFromUrl(url);
            return OM.readValue(contents, LinkedHashMap.class);
        } catch (JsonParseException | JsonMappingException e) {
            logger.error("Failed to parse contents retrieved from url {}: {}", url, e.toString());
            throw e;
        }
    }

    /**
     * Queries and gets the contents of a given url, returning the result as a String. Will attempt to pull data
     * for maxAttemptsPerPage attempts, throwing an IOException error upon failure.
     *
     * @param url url to query
     * @return String contents of url
     * @throws IOException if an error occurs while parsing the given url
     */
    private static String getContentFromUrl(String url) throws IOException {
        StringBuilder response = new StringBuilder();
        BufferedReader bufferedReader;

        int attempts = 0;

        while (attempts < maxAttemptsPerPage) {
            try {
                URL urlObject = new URL(url);
                HttpURLConnection httpURLConnection = (HttpURLConnection) urlObject.openConnection();
                httpURLConnection.setRequestMethod("GET");
                httpURLConnection.setRequestProperty("User-Agent", userAgent);
                httpURLConnection.setRequestProperty("Accept-Encoding", "identity");

                // Rate limit protection
                if (httpURLConnection.getResponseCode() == 403) {
                    throw new IOException(String.format("URL '%s' responded with 403 - Forbidden. It is likely that rate limiting has been triggered.", url));
                }

                // Service Unavailable error
                if (httpURLConnection.getResponseCode() == 503) {
                    throw new IOException(String.format("URL '%s' responded with 503 - Service Unavailable. The page was unable to be loaded.", url));
                }

                bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
                String inputLine;
                while ((inputLine = bufferedReader.readLine()) != null) {
                    response.append(inputLine).append("\n");
                }
                bufferedReader.close();

                return response.toString();

            // If error occurs, increment attempts and sleep for 30 seconds before retrying
            } catch (IOException e) {
                attempts++;

                try {
                    // Even if on last attempt, still sleep
                    if (attempts == maxAttemptsPerPage) {
                        logger.error("Error: {}", e.toString());
                        logger.info("Attempt {}/{} failed, sleeping for 30s before proceeding to next page...", attempts, maxAttemptsPerPage);
                        Thread.sleep(30000);

                    } else {
                        logger.error("Error: {}", e.toString());
                        logger.info("Attempt {}/{} failed, sleeping for 30s before retrying query...", attempts, maxAttemptsPerPage);
                        Thread.sleep(30000);
                    }
                } catch (InterruptedException ignored) {}
            }
        }

        throw new IOException();
    }
}

