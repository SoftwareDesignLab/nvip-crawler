package edu.rit.se.nvip.utils.metrics;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.rit.se.nvip.model.RawVulnerability;
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
    // todo also need versions of all of these that take a filter setting arg (all, local, individual)

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
        Set<RawVulnerability> rawVulns = new HashSet<>(); //all raw vulns that have been found

        for(CrawlerRun run: runs){
            int vulns = 0; //initializing number of vulns that were found

            //for each raw vuln that exists in the run
            for(RawVulnerability vuln : run.getVulns()){
                //if the raw vuln is new: meaning it doesn't exist in any previous run and the raw_description_ids are different
                if(!rawVulns.contains(vuln)){
                    rawVulns.add(vuln); //add the new vuln to the list of rawVulns that exists
                    vulns++; //increase number of new vulns
                }
            }
            runMap.put(run, vulns);//add the run and the amount of new vulns that were found to the map
        }

        return runMap;
    }

    public List<Map<RawVulnerability.SourceType, Integer>> sourceTypeDistribution() {

        List<Map<RawVulnerability.SourceType, Integer>> typeDistributionMap = new ArrayList<>();
        for(CrawlerRun run: runs) {
            Map<RawVulnerability.SourceType, Integer> map = new HashMap<>(); // for every run make a new map
            int cna = 0; //initialize source variables
            int sa = 0;
            int third_party = 0;
            int bug_bounty = 0;
            int other = 0;
            //for each raw vuln that exists in the run
            for (RawVulnerability vuln : run.getVulns()) {
                //get the source type and increase the value of that source type
                if (vuln.getSourceType() == RawVulnerability.SourceType.CNA){
                    cna++;
                }else if (vuln.getSourceType() == RawVulnerability.SourceType.SA){
                    sa++;
                }else if (vuln.getSourceType() == RawVulnerability.SourceType.THIRD_PARTY) {
                    third_party++;
                }else if (vuln.getSourceType() == RawVulnerability.SourceType.BUG_BOUNTY){
                    bug_bounty++;
                }else if (vuln.getSourceType() == RawVulnerability.SourceType.OTHER){
                    other++;
                }
            }

            //put the values in the map SourceType, Amount of sources from that type
            map.put(RawVulnerability.SourceType.CNA, cna);
            map.put(RawVulnerability.SourceType.SA, sa);
            map.put(RawVulnerability.SourceType.THIRD_PARTY, third_party);
            map.put(RawVulnerability.SourceType.BUG_BOUNTY, bug_bounty);
            map.put(RawVulnerability.SourceType.OTHER, other);

            //add the map to the list of maps (array of maps)
            typeDistributionMap.add(map);
        }

        return typeDistributionMap;
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

    public Map<CrawlerRun, Double> proportionPassed() {

        Map<CrawlerRun, Double> proportions = new HashMap<>(); //map of runs to percentages
        if (runs == null){ //case for if method is called and runs are not properly initialized
            logger.error("There are no Crawler Runs found");
            return null;
        }

        Map<CrawlerRun, FilterStats> runMap = numFiltered(); //gets filter stats used to get proportions

        for (CrawlerRun run : runMap.keySet()){ // for every run

            FilterStats filterStats = runMap.get(run); //get the filter stats for every run

            if (filterStats.getTotalFiltered() == 0){ //case for if there are no vulnerabilities that were filtered
                logger.error("Trying to divide by 0 because Total Vulns filtered is 0");
                return null;
            }

            double proportion = (double) filterStats.getPassedFilters() / filterStats.getTotalFiltered(); //get the proportion of passed to total vulns

            proportions.put(run, proportion); //map each run to the proportion of passed filtered vulns
        }

        return proportions;
    }
}
