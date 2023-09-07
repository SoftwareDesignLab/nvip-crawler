package edu.rit.se.nvip.utils.metrics;

import edu.rit.se.nvip.filter.FilterStatus;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.model.SourceType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

public class CrawlerRun {
    private Set<RawVulnerability> vulns;
    private int runId;
    private Date runDate;
    private static final Logger logger = LogManager.getLogger(CrawlerRun.class.getSimpleName());
    public CrawlerRun(Set<RawVulnerability> vulns, int runId, Date runDate) {
        this.vulns = vulns;
        this.runId = runId;
        this.runDate = runDate;
    }

    public int newVulnsPerRun(Set<RawVulnerability> foundAlready) {
        int numVulns = 0; //initializing number of vulns that were found
        //for each raw vuln that exists in the run
        for(RawVulnerability vuln : vulns){
            //a raw vuln is new if its id (integer, assigned by database upon crawler insertion) hasn't appeared in a previous run
            if(isNew(vuln, foundAlready)){
                foundAlready.add(vuln); //add the new vuln to the list of rawVulns that exists
                numVulns++; //increase number of new vulns
            }
        }
        return numVulns;
    }

    private boolean isNew(RawVulnerability candidate, Set<RawVulnerability> previous) {
        //return previous.stream().map(RawVulnerability::getId).collect(Collectors.toSet()).contains(candidate.getId()); // if we have unique ids from the crawler, we can use this
        return previous.stream().filter(p -> p.generalEquals(candidate)).collect(Collectors.toSet()).size() == 0;
    }

    public Map<SourceType, Integer> sourceTypeDistribution() {
        Map<SourceType, Integer> map = new HashMap<>(); // for every run make a new map
        int cna = 0; //initialize source variables
        int sa = 0;
        int third_party = 0;
        int bug_bounty = 0;
        int other = 0;
        //for each raw vuln that exists in the run
        for (RawVulnerability vuln : vulns) {
            //get the source type and increase the value of that source type
            if (vuln.getSourceType() == SourceType.CNA){
                cna++;
            }else if (vuln.getSourceType() == SourceType.SA){
                sa++;
            }else if (vuln.getSourceType() == SourceType.THIRD_PARTY) {
                third_party++;
            }else if (vuln.getSourceType() == SourceType.BUG_BOUNTY){
                bug_bounty++;
            }else if (vuln.getSourceType() == SourceType.OTHER){
                other++;
            }
        }
        //put the values in the map SourceType, Amount of sources from that type
        map.put(SourceType.CNA, cna);
        map.put(SourceType.SA, sa);
        map.put(SourceType.THIRD_PARTY, third_party);
        map.put(SourceType.BUG_BOUNTY, bug_bounty);
        map.put(SourceType.OTHER, other);
        return map;
    }

    public FilterStats numFiltered() {
        FilterStats filterStats = new FilterStats(); //create a new stat tracker

        for(RawVulnerability vuln : vulns){ //for each vuln in the run

            if (vuln.getFilterStatus() == FilterStatus.UNEVALUATED || vuln.getFilterStatus() == FilterStatus.NEW){ //if it's NEW or UNEVALUATED we consider it not filtered
                filterStats.increaseNotFiltered();
            }
            else if (vuln.getFilterStatus() == FilterStatus.PASSED){ //if it passed then it filtered
                filterStats.increasePassedFilters();
            }
            else if (vuln.getFilterStatus() == FilterStatus.FAILED){ //if it failed then it failed to fully filter
                filterStats.increaseFailedFilters();
            }

            if (vuln.isFiltered()){
                filterStats.increaseTotalFiltered(); //total amount filtered at all
            }

            filterStats.increaseTotalVulns(); //total amount of vulns
        }
        return filterStats;
    }

    public double proportionPassed() {
        FilterStats stats = this.numFiltered();
        if (stats.getTotalFiltered() == 0){ //case for if there are no vulnerabilities that were filtered
            logger.error("Trying to divide by 0 because Total Vulns filtered is 0");
            return 0;
        }

        return ((double) stats.getPassedFilters()) / stats.getTotalFiltered(); //get the proportion of passed to total vulns
    }

    public Set<RawVulnerability> getVulns(){return this.vulns;}

    public Date getDate(){return this.runDate;}

    public int getRunId() {
        return this.runId;
    }

    public void resetFilterStatus() {
        for (RawVulnerability vuln : vulns) {
            vuln.setFilterStatus(FilterStatus.NEW);
        }
    }


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

}
