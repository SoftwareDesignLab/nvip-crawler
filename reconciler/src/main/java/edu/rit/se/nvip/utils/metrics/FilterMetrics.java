package edu.rit.se.nvip.utils.metrics;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;

public class FilterMetrics {
    private List<CrawlerRun> runs = new ArrayList<>();
    private static final Logger logger = LogManager.getLogger(FilterMetrics.class.getSimpleName());

    public static class FilterStats {
        /*

        NEW FILTER STATS CLASS USED IN numFiltered() TO TRACK CERTAIN FILTER STATS
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

        List<File> jsonFiles = findJsonFiles(directory); //gets the Json files
        for (File file : jsonFiles) { //for each jsonFile

            Set<RawVulnerability> rawVulns = processJSONFiles(file);
            Date date = new Date();

            CrawlerRun run = new CrawlerRun(rawVulns, runId, date); //creates new run from json

            runs.add(run);
            runId++;


        }
        // todo read in each json from the directory into CrawlerRun
    }
    // todo also need versions of all of these with a parser type arg, where only results for that parser are returned
    // todo also need versions of all of these that take a filter setting arg (all, local, individual)

    //Helper function for getting a list of Json files that were in the directory
    private List<File> findJsonFiles(File directory) {
        List<File> jsonFiles = new ArrayList<>();//new list of jsons
        File[] files = directory.listFiles();//gets every file in the directory

        if (files != null) { //if the directory isn't empty
            for (File file : files) {
                if (file.isFile() && file.getName().toLowerCase().endsWith(".json")) { //if the file is "normal" meaning it isn't a directory and the file ends in .json
                    jsonFiles.add(file); //add the file to the list
                }
            }
        }
        else{
            logger.error("Directory is empty!");
        }

        return jsonFiles;
    }

    //Processes the json and makes the raw vulns from the json
    private static Set<RawVulnerability> processJSONFiles(File jsonFile) {
        Set<RawVulnerability> rawVulnerabilities = new HashSet<>();


        try (BufferedReader reader = new BufferedReader(new FileReader(jsonFile))) {
            StringBuilder jsonString = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonString.append(line);
            }

            JsonArray jsonArray = JsonParser.parseString(jsonString.toString()).getAsJsonArray();

            for (JsonElement jsonElement : jsonArray) {
                JsonObject jsonObject = jsonElement.getAsJsonObject();

                // Extract values from the JSON object
                int rawDescId = jsonObject.get("raw_desc_id").getAsInt();
                String rawDesc = jsonObject.get("raw_desc").getAsString();
                String cveId = jsonObject.get("cve_id").getAsString();
                String createdDate = jsonObject.get("created_date").getAsString();
                String publishedDate = jsonObject.get("published_date").getAsString();
                String lastModifiedDate = jsonObject.get("last_modified_date").getAsString();
                String sourceUrl = jsonObject.get("source_url").getAsString();
                int isGarbage = jsonObject.get("is_garbage").getAsInt();


                // Create RawVulnerability object
                RawVulnerability rawVuln = new RawVulnerability(rawDescId, cveId, rawDesc, Timestamp.valueOf(publishedDate), Timestamp.valueOf(lastModifiedDate), Timestamp.valueOf(createdDate), sourceUrl);

                // Add the rawVulnerability object to the set
                rawVulnerabilities.add(rawVuln);
            }
        } catch (IOException e) {
            logger.error("IO Exception error");
        }


        return rawVulnerabilities;
    }

    /*
    Checks to see how many "new" vulnerabilities were found
    Where "new" means that the tuple (CVE_ID, Description, Source_URL) doesn't match any entries from prior runs
     */
    public Map<CrawlerRun, Integer> newVulnsPerRun() {

        Map<CrawlerRun, Integer> runMap = new HashMap<>(); //Map of runs to number of new raw vulns
        List<RawVulnerability> rawVulns = new ArrayList<>(); //all raw vulns that have been found

        for(CrawlerRun run: runs){
            int vulns = 0; //initializing number of vulns that were found

            //for each raw vuln that exists in the run
            for(RawVulnerability vuln : run.getVulns()){
                //if the raw vuln is new: meaning it doesn't exist in any previous run
                if(!rawVulns.contains(vuln)){
                    rawVulns.add(vuln); //add the new vuln to the list of rawVulns that exists
                    vulns++; //increase number of new vulns
                }
            }
            runMap.put(run, vulns);//add the run and the amount of new vulns that were found to the map
        }

        return runMap;
    }

    public Map<RawVulnerability.SourceType, Integer>[] sourceTypeDistribution() {
        return null;
    }

    public Map<CrawlerRun, FilterStats> numFiltered() {

        Map<CrawlerRun, FilterStats> filteredStats = new HashMap<>(); //Map of runs to its filter stats meaning total number of: notFiltered, passedFilters, failedFilters, totalVulns, totalFiltered

        for (CrawlerRun run : runs){ //for each run

            FilterStats filterStats = new FilterStats(); //create a new stat tracker

            for(RawVulnerability vuln : run.getVulns()){ //for each vuln in the run

                if (vuln.getFilterStatus() == RawVulnerability.FilterStatus.UNEVALUATED || vuln.getFilterStatus() == RawVulnerability.FilterStatus.NEW){ //if it's NEW or UNEVALUATED we consider it not filtered
                    filterStats.increaseNotFiltered();
                }
                else if (vuln.getFilterStatus() == RawVulnerability.FilterStatus.PASSED){ //if it passed then it filtered
                    filterStats.increasePassedFilters();
                }
                else if (vuln.getFilterStatus() == RawVulnerability.FilterStatus.FAILED){ //if it failed then it failed to fully filter
                    filterStats.increaseFailedFilters();
                }

                if (vuln.isFiltered()){
                    filterStats.increaseTotalFiltered(); //total amount filtered at all
                }

                filterStats.increaseTotalVulns(); //total amount of vulns
            }

            filteredStats.put(run, filterStats);
        }

        return filteredStats;
    }

    public double[] proportionPassed() {
        return null;
    }
}
