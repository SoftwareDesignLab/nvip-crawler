/ **
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
* /

package edu.rit.se.nvip.db.model;

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
        this.notInNvdCount = filterThenCount(reconciledVulns, v -> !v.isInNvd());
        this.notInMitreCount = filterThenCount(reconciledVulns, v -> !v.isInMitre());
        this.notInBothCount = filterThenCount(reconciledVulns, v -> !v.isInNvd() && !v.isInMitre());
        this.avgTimeGapNvd = 0; // todo figure out what on earth this means, need input from Mehdi
        this.avgTimeGapMitre = this.avgTimeGapNvd; //  set this to the same as timeGapNvd, that's what the old code does because mitre records usually don't have dates
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
