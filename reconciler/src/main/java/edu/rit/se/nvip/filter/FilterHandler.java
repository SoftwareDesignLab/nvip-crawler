package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.*;

public class FilterHandler {
    List<Filter> localFilters;
    List<Filter> remoteFilters;

    public enum FilterSetting {
        ALL, LOCAL, REMOTE,
    }

    public void runFilters(Set<RawVulnerability> vulns, FilterSetting setting) {

    }

    private void runFilters(Set<RawVulnerability> vulns, List<Filter> filters, boolean handleDiffCvesSeparately) {
        if (handleDiffCvesSeparately) {
            Map<String, Set<RawVulnerability>> cves = partitionByCve(vulns);
            for (String id : cves.keySet()) {
                //todo filter
            }
        }
        Map<String, Set<RawVulnerability>> equivClasses = partitionByDesc(vulns);
    }

    private Map<String, Set<RawVulnerability>> partitionByDesc(Set<RawVulnerability> vulns) {
        return null;
    }

    private Map<String, Set<RawVulnerability>> partitionByCve(Set<RawVulnerability> vulns) {
        Map<String, Set<RawVulnerability>> out = new HashMap<>();
        for (RawVulnerability vuln : vulns) {
            String id = vuln.getCveId();
            if (!out.containsKey(id)) {
                Set<RawVulnerability> newSet = new HashSet<>();
                out.put(id, newSet);
            }
            out.get(id).add(vuln);
        }
        return out;
    }
}
