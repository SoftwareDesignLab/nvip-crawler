package edu.rit.se.nvip.reconciler.filter;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.*;
import java.util.stream.Collectors;

public class FilterHandler {
    private final List<Filter> localFilters = new ArrayList<>();
    private final List<Filter> remoteFilters = new ArrayList<>();
    private List<Filter> customFilters = new ArrayList<>();
    public enum FilterScope {
        ALL, CUSTOM, LOCAL, REMOTE
    }

    public FilterHandler() {
        initializeLocalFilters();
    }

    public FilterHandler(List<String> extraFilterTypes) {
        this();
        initializeRemoteFilters(extraFilterTypes);
    }

    private void initializeLocalFilters() {
        localFilters.add(new BlankDescriptionFilter());
        localFilters.add(new CveMatchesDescriptionFilter());
        localFilters.add(new IntegerDescriptionFilter());
        localFilters.add(new MultipleCveDescriptionsFilter());
        localFilters.add(new DescriptionSizeFilter());
    }

    private void initializeRemoteFilters(List<String> filterTypes) {
        for (String type : filterTypes) {
            remoteFilters.add(FilterFactory.createFilter(type));
        }
    }

    public void setCustomFilters(List<Filter> customFilters) {
        this.customFilters = customFilters;
    }

    public FilterReturn runFilters(Set<RawVulnerability> vulns) {
        return runFilters(vulns, FilterScope.ALL, false);
    }


    public FilterReturn runFilters(Set<RawVulnerability> vulns, FilterScope scope, boolean filterDiffCvesSeparately) {
        List<Filter> filters = getFiltersByScope(scope);
        return runFilters(vulns, filters, filterDiffCvesSeparately);
    }

    public FilterReturn runFilters(Set<RawVulnerability> vulns, List<Filter> filters, boolean filterDiffCvesSeparately) {
        FilterReturn out = new FilterReturn(0, 0, 0);
        if (filterDiffCvesSeparately) {
            Map<String, Set<RawVulnerability>> cves = partitionByCve(vulns);
            for (String id : cves.keySet()) {
                out.add(runFiltersByEquivClasses(cves.get(id), filters));
            }
        } else {
            out.add(runFiltersByEquivClasses(vulns, filters));
        }
        return out;
    }

    private FilterReturn runFiltersByEquivClasses(Set<RawVulnerability> vulns, List<Filter> filters) {
        // set up equivalence classes partitioned by equal descriptions
        Map<String, Set<RawVulnerability>> equivClasses = new HashMap<>();
        Set<RawVulnerability> samples = new HashSet<>(); // holds one from each equivalence class
        for (RawVulnerability rawVuln : vulns) {
            String desc = rawVuln.getDescription().trim();
            if (!equivClasses.containsKey(desc)) {
                equivClasses.put(desc, new HashSet<>());
                samples.add(rawVuln);
            }
            equivClasses.get(desc).add(rawVuln);
        }
        for (Filter filter : filters) {
            filter.filterAll(samples); // todo filters should always operate on trimmed descriptions, need to architect this properly for consistency
        }
        // update filter statuses in each equiv class to match its sample
        for (RawVulnerability sample : samples) {
            for (RawVulnerability rv : equivClasses.get(sample.getDescription().trim())) {
                rv.setFilterStatus(sample.getFilterStatus());
            }
        }
        int nPassed = vulns.stream().filter(v->v.getFilterStatus()== RawVulnerability.FilterStatus.PASSED).collect(Collectors.toSet()).size();
        return new FilterReturn(vulns.size(), samples.size(), nPassed);
    }

    private List<Filter> getFiltersByScope(FilterScope scope) {
        List<Filter> out = new ArrayList<>();
        if (scope == FilterScope.ALL) {
            out.addAll(localFilters);
            out.addAll(remoteFilters);
        } else if (scope == FilterScope.LOCAL) {
            out.addAll(localFilters);
        } else if (scope == FilterScope.REMOTE) {
            out.addAll(remoteFilters);
        } else if (scope == FilterScope.CUSTOM) {
            out.addAll(customFilters);
        }
        return out;
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

    public List<Filter> getCustomFilters() {
        return customFilters;
    }
}
