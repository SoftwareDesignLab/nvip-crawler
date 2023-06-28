package edu.rit.se.nvip.utils.metrics;

import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FilterMetrics {
    private List<CrawlerRun> runs = new ArrayList<>();
    private static final Logger logger = LogManager.getLogger(FilterMetrics.class.getSimpleName());

    public FilterMetrics(String directoryPath) {

        File directory = new File(directoryPath); //grabs the directory from the directoryPath
        if (!directory.isDirectory()) { //checks to make sure the directory exists
            logger.error("Invalid directory path");
            return;
        }

        List<File> jsonFiles = findJsonFiles(directory); //gets the Json files
        for (File file : jsonFiles) { //for each jsonFile
            //iterate through and get raw vulns


        }
        // todo read in each json from the directory into CrawlerRun
    }
    // todo also need versions of all of these with a parser type arg, where only results for that parser are returned
    // todo also need versions of all of these that take a filter setting arg (all, local, individual)

    //Helper function for getting a list of Json files that were in the directory
    private List<File> findJsonFiles(File directory) {
        List<File> jsonFiles = new ArrayList<>();
        File[] files = directory.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().toLowerCase().endsWith(".json")) {
                    jsonFiles.add(file);
                }
            }
        }

        return jsonFiles;
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

    public int[] numFiltered() {
        return null;
    }

    public double[] proportionPassed() {
        return null;
    }
}
