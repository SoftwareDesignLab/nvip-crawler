/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package edu.rit.se.nvip.utils.metrics;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

public class CrawlerRun {
    private Set<RawVulnerability> vulns;
    private int runId;
    private Date runDate;
    private static final Logger logger = LogManager.getLogger(FilterMetrics.class.getSimpleName());
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

    public Map<RawVulnerability.SourceType, Integer> sourceTypeDistribution() {
        Map<RawVulnerability.SourceType, Integer> map = new HashMap<>(); // for every run make a new map
        int cna = 0; //initialize source variables
        int sa = 0;
        int third_party = 0;
        int bug_bounty = 0;
        int other = 0;
        //for each raw vuln that exists in the run
        for (RawVulnerability vuln : vulns) {
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
        return map;
    }

    public FilterMetrics.FilterStats numFiltered() {
        FilterMetrics.FilterStats filterStats = new FilterMetrics.FilterStats(); //create a new stat tracker

        for(RawVulnerability vuln : vulns){ //for each vuln in the run

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
        return filterStats;
    }

    public double proportionPassed() {
        FilterMetrics.FilterStats stats = this.numFiltered();
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
            vuln.setFilterStatus(RawVulnerability.FilterStatus.NEW);
        }
    }

}
