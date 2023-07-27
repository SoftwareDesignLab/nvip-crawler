package edu.rit.se.nvip.model;

import java.sql.Timestamp;
import java.util.Set;
import java.util.function.Predicate;

public class RunStats {
    private final Timestamp runDateTime;
    private final int totalCveCount;
    private final int newCveCount;
    private final int updatedCveCount;
    private final int notInNvdCount;
    private final int notInMitreCount;
    private final int notInBothCount;
    private final double avgTimeGapNvd;
    private final double avgTimeGapMitre;

    public RunStats(Set<CompositeVulnerability> reconciledVulns) {
        this.runDateTime = new Timestamp(System.currentTimeMillis());
        this.totalCveCount = reconciledVulns.size();
        this.newCveCount = filterThenCount(reconciledVulns, v -> v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW);
        this.updatedCveCount = filterThenCount(reconciledVulns, v -> v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UNCHANGED);
        this.notInNvdCount = filterThenCount(reconciledVulns, v -> v.getInNvd() == 0);
        this.notInMitreCount = 0; // todo implement this when we have mitre comparisons
        this.notInBothCount = 0; // todo
        this.avgTimeGapNvd = 0; // todo compute this when the nvd status gets checked
        this.avgTimeGapMitre = 0; // todo set this to the same as timeGapNvd, that's what the old code does because mitre records usually don't have dates
    }

    private int filterThenCount(Set<CompositeVulnerability> vulns, Predicate<CompositeVulnerability> filterFunc) {
        return (int) vulns.stream().filter(filterFunc).count();
    }

    public Timestamp getRunDateTime() {
        return runDateTime;
    }

    public int getTotalCveCount() {
        return totalCveCount;
    }

    public int getNewCveCount() {
        return newCveCount;
    }

    public int getUpdatedCveCount() {
        return updatedCveCount;
    }

    public int getNotInNvdCount() {
        return notInNvdCount;
    }

    public int getNotInMitreCount() {
        return notInMitreCount;
    }

    public int getNotInBothCount() {
        return notInBothCount;
    }

    public double getAvgTimeGapNvd() {
        return avgTimeGapNvd;
    }

    public double getAvgTimeGapMitre() {
        return avgTimeGapMitre;
    }
}
