package edu.rit.se.nvip.utils.metrics;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.Date;
import java.util.Set;

public class CrawlerRun {
    private Set<RawVulnerability> vulns;
    private int runId;
    private Date runDate;
    public CrawlerRun(Set<RawVulnerability> vulns, int runId, Date runDate) {
        this.vulns = vulns;
        this.runId = runId;
        this.runDate = runDate;
    }

    public Set<RawVulnerability> getVulns(){return this.vulns;}

}
