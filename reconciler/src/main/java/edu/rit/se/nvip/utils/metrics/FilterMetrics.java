package edu.rit.se.nvip.utils.metrics;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterHandler;
import edu.rit.se.nvip.filter.FilterReturn;
import edu.rit.se.nvip.model.RawVulnerability;
import jdk.internal.util.SystemProps;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;

public class FilterMetrics {
    private List<CrawlerRun> runs = new ArrayList<>();
    private FilterHandler filterHandler = new FilterHandler();
    private FilterHandler.FilterScope filterScope = FilterHandler.FilterScope.ALL;
    private static final Logger logger = LogManager.getLogger(FilterMetrics.class.getSimpleName());

    public static class FilterStats {
        /*

        NEW FILTER STATS INNER CLASS USED IN numFiltered() TO TRACK CERTAIN FILTER STATS
        CHECKS TO SEE HOW MANY PASSED, HOW MANY FAILED, HOW MANY TOTAL VULNS, HOW MANY TOTAL WERE FILTERED, AND HOW MANY WERE NOT FILTERED

         */
        private int notFiltered;
        private int passedFilters;
        private int failedFilters;
        private int totalVulns;
        private int totalFiltered;

        public FilterStats() {
            this.notFiltered = 0;
            this.passedFilters = 0;
            this.failedFilters = 0;
            this.totalVulns = 0;
            this.totalFiltered = 0;
        }
        public int getPassedFilters(){ return this.passedFilters;}
        public int getTotalFiltered(){ return this.totalFiltered;}
        public int getTotalVulns(){ return this.totalVulns;}
        public int getTotalFailed(){ return this.failedFilters;}
        public int getTotalNotFiltered(){ return this.notFiltered;}

        public void increaseNotFiltered() {
            this.notFiltered++;
        }

        public void increasePassedFilters() {
            this.passedFilters++;
        }

        public void increaseFailedFilters() {
            this.failedFilters++;
        }

        public void increaseTotalVulns() {
            this.totalVulns++;
        }

        public void increaseTotalFiltered() {
            this.totalFiltered++;
        }

    }

    public FilterMetrics(String directoryPath) {
        int runId = 1;
        File directory = new File(directoryPath); //grabs the directory from the directoryPath
        if (!directory.isDirectory()) { //checks to make sure the directory exists
            logger.error("Invalid directory path");
            return;
        }
        applyFilters();
        List<File> jsonFiles = findJsonFiles(directory); //gets the Json files
        for (File file : jsonFiles) { //for each jsonFile
            Set<RawVulnerability> rawVulns = processJSONFiles(file);
            Date date = extractDateFromFilename(file.getName()); //gets the date from the file name
            CrawlerRun run = new CrawlerRun(rawVulns, runId, date); //creates new run from json
            runs.add(run);
            runId++;
        }
    }

    /**
     * Constructor with args for using a custom set of filters
     * @param directoryPath path of directory containing crawler output jsons
     * @param handler FilterHandler object with updated custom filters var
     * @param scope FilterScope for defining scope of filters to use (custom, all, local, remote)
     */
    public FilterMetrics(String directoryPath, FilterHandler handler, FilterHandler.FilterScope scope) {
        int runId = 1;
        File directory = new File(directoryPath); //grabs the directory from the directoryPath
        if (!directory.isDirectory()) { //checks to make sure the directory exists
            logger.error("Invalid directory path");
            return;
        }
        filterHandler = handler;
        filterScope = scope;
        applyFilters();
        List<File> jsonFiles = findJsonFiles(directory); //gets the Json files
        for (File file : jsonFiles) { //for each jsonFile
            Set<RawVulnerability> rawVulns = processJSONFiles(file);
            Date date = extractDateFromFilename(file.getName()); //gets the date from the file name
            CrawlerRun run = new CrawlerRun(rawVulns, runId, date); //creates new run from json
            runs.add(run);
            runId++;
        }
    }
    // todo also need versions of all of these with a parser type arg, where only results for that parser are returned

    public static Date extractDateFromFilename(String filename) {
        String dateString = filename.substring(filename.lastIndexOf("_") + 1, filename.lastIndexOf(".")); //gets the date portion of the file
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HHmmss.SSSSSS"); //initiates new DataFormat


        try {
            return format.parse(dateString); //returns the new Date
        } catch (ParseException e) {
            logger.error("Problem retrieving Date from file");
            return null;
        }
    }

    //Helper function for getting a list of Json files that were in the directory
    private List<File> findJsonFiles(File directory) {
        List<File> jsonFiles = new ArrayList<>();

        if (directory.isDirectory()) {
            File[] files = directory.listFiles();

            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.getName().toLowerCase().endsWith(".json")) {
                        jsonFiles.add(file);
                    }
                }
            } else {
                logger.error("Directory is empty!");
            }
        } else {
            logger.error("Invalid directory path");
        }

        return jsonFiles;
    }

    //Processes the json and makes the raw vulns from the json
    private static Set<RawVulnerability> processJSONFiles(File jsonFile) {
        Set<RawVulnerability> rawVulnerabilities = new HashSet<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(jsonFile))) {
            StringBuilder jsonContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonContent.append(line);
            }

            JsonObject jsonObject = JsonParser.parseString(jsonContent.toString()).getAsJsonObject();

            for (String key : jsonObject.keySet()) {
                JsonElement jsonElement = jsonObject.get(key);

                if (jsonElement.isJsonArray()) {
                    // Process the array of objects associated with the key
                    for (JsonElement element : jsonElement.getAsJsonArray()) {
                        JsonObject innerObject = element.getAsJsonObject();

                        // Extract values from the JSON object
                        String sourceURL = innerObject.get("sourceURL").getAsString();
                        String sourceType = innerObject.get("sourceType").getAsString();
                        int vulnID = innerObject.get("vulnID").getAsInt();
                        String cveId = innerObject.get("cveId").getAsString();
                        String description = innerObject.get("description").getAsString();
                        String publishedDate = innerObject.get("publishDate").getAsString();
                        String createdDate = innerObject.get("createDate").getAsString();
                        String lastModifiedDate = innerObject.get("lastModifiedDate").getAsString();

                        // Create RawVulnerability object
                        RawVulnerability rawVuln = new RawVulnerability(vulnID, cveId, description, Timestamp.valueOf(publishedDate), Timestamp.valueOf(lastModifiedDate), Timestamp.valueOf(createdDate), sourceURL, sourceType, 1);

                        // Add the rawVulnerability object to the set
                        rawVulnerabilities.add(rawVuln);
                    }
                }
            }
        } catch (IOException e) {
            logger.error("IO Exception error");
        }

        return rawVulnerabilities;
    }

    public List<CrawlerRun> getRuns(){
        return this.runs;
    }
    /*
    Checks to see how many "new" vulnerabilities were found
    Where "new" means that the tuple (CVE_ID, Description, Source_URL) doesn't match any entries from prior runs
     */
    public Map<CrawlerRun, Integer> newVulnsPerRun() {
        Map<CrawlerRun, Integer> runMap = new HashMap<>(); //Map of runs to number of new raw vulns
        Set<RawVulnerability> foundVulns = new HashSet<>();
        for(CrawlerRun run: runs){
            runMap.put(run, run.newVulnsPerRun(foundVulns));//add the run and the amount of new vulns that were found to the map
        }
        return runMap;
    }

    public List<Map<RawVulnerability.SourceType, Integer>> sourceTypeDistribution() {
        List<Map<RawVulnerability.SourceType, Integer>> typeDistributionMap = new ArrayList<>();
        for(CrawlerRun run: runs) {
            Map<RawVulnerability.SourceType, Integer> map = run.sourceTypeDistribution();
            typeDistributionMap.add(map);
        }
        return typeDistributionMap;
    }

    public Map<CrawlerRun, FilterStats> numFiltered() {
        Map<CrawlerRun, FilterStats> filteredStats = new HashMap<>(); //Map of runs to its filter stats meaning total number of: notFiltered, passedFilters, failedFilters, totalVulns, totalFiltered
        for (CrawlerRun run : runs){ //for each run
            FilterStats filterStats = run.numFiltered();
            filteredStats.put(run, filterStats);
        }
        return filteredStats;
    }

    public Map<CrawlerRun, Double> proportionPassed() {
        Map<CrawlerRun, Double> proportions = new HashMap<>(); //map of runs to percentages
        if (runs == null){ //case for if method is called and runs are not properly initialized
            logger.error("There are no Crawler Runs found");
            return null;
        }
        Map<CrawlerRun, FilterStats> runMap = numFiltered(); //gets filter stats used to get proportions
        for (CrawlerRun run : runMap.keySet()){ // for every run
            proportions.put(run, run.proportionPassed()); //map each run to the proportion of passed filtered vulns
        }
        return proportions;
    }

    /**
     * Helper method for setting a new list of custom filters
     * @param customFilters list of Filters
     */
    public void setCustomFilters(List<Filter> customFilters) {
        filterHandler.setCustomFilters(customFilters);
        resetFilterStatus();
        applyFilters();
    }

    /**
     * Helper method for setting a new filter scope
     * @param filterScope new filter scope
     */
    public void setFilterScope(FilterHandler.FilterScope filterScope) {
        this.filterScope = filterScope;
        resetFilterStatus();
        applyFilters();
    }

    /**
     * Resets all RawVulnerabilities' filter status to NEW
     */
    private void resetFilterStatus() {
        for (CrawlerRun run: getRuns()) {
            run.resetFilterStatus();
        }
    }

    /**
     * Helper method for applying set of filters to all sets of RawVulns in current CrawlerRuns
     */
    private void applyFilters() {
        for (CrawlerRun run: getRuns()) {
            filterHandler.runFilters(run.getVulns(), filterScope, false);
        }
    }
}
