package edu.rit.se.nvip.utils.metrics;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class FilterMetrics {
    private List<Set<RawVulnerability>> runs;
    public FilterMetrics(String directoryPath) {
        // todo read in each json from the directory into a set of rawvulns
    }
    // todo also need versions of all of these with a parser type arg, where only results for that parser are returned
    // todo also need versions of all of these that take a filter setting arg (all, local, individual)
    public int[] newVulnsPerRun() {
        return null;
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
