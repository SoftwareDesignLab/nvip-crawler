package edu.rit.se.nvip.reconciler;

import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterChain;
import edu.rit.se.nvip.filter.FilterResult;
import edu.rit.se.nvip.filter.FilterStatus;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.model.SourceType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class VulnBuilder {

    private Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private CompositeVulnerability existing;
    Set<RawVulnerability> allSources;
    RawVulnerability userSource;

    public VulnBuilder(CompositeVulnerability existing) {
        this.existing = existing;
    }

    public CompositeVulnerability filterAndBuild(Set<RawVulnerability> allSources, FilterChain filterChain, Reconciler reconciler) {
        this.allSources = allSources;
        Set<RawVulnerability> newPassedSources = runFiltersOnScrapedSources(filterChain);
        return reconciler.reconcile(existing, newPassedSources);
    }

    public CompositeVulnerability overrideWithUser(RawVulnerability userSource) {
        this.userSource = userSource;
        // todo complete
        return null;
    }
    private Set<RawVulnerability> runFiltersOnScrapedSources(FilterChain filterChain) {
        Set<RawVulnerability> newSources = filterByFilterStatus(allSources, FilterStatus.NEW);
        Set<RawVulnerability> existingSources = filterToSet(allSources, rv->!newSources.contains(rv));
        Map<RawVulnerability, FilterResult> newSourceToFilterStatus = filterChain.runFilters(newSources, existingSources);
        sortByPrio(newSourceToFilterStatus.keySet()).forEach(rv->updateFilterStatus(rv, newSourceToFilterStatus.get(rv)));
        return filterByFilterStatus(newSourceToFilterStatus.keySet(), FilterStatus.PASSED);
    }

    private void updateFilterStatus(RawVulnerability rv, FilterResult fr) {
        switch(fr.getStatus()) {
            case UNEVALUATED:
                logger.info("CVE {} from source {} with vuln_id {} was skipped by NVIP's filtering system due to being a low priority source",
                        rv.getCveId(), rv.getSourceUrl(), rv.getVulnID());
            case PASSED:
                logger.info("CVE {} from source {} with vuln_id {} passed all NVIP quality filters",
                        rv.getCveId(), rv.getSourceUrl(), rv.getVulnID());
            case FAILED:
                if (fr.getFailedAt() == null) {
                    logger.info("CVE {} from source {} with vuln_id {} was rejected by NVIP's filters because its data is equivalent to a previously rejected source",
                            rv.getCveId(), rv.getSourceUrl(), rv.getVulnID());
                } else {
                    logger.info("CVE {} from source {} with vuln_id {} was rejected by NVIP's filters at the {} stage.",
                            rv.getCveId(), rv.getSourceUrl(), rv.getVulnID(), fr.getFailedAt());
                }
        }
        rv.setFilterStatus(fr.getStatus());
    }

    private static Set<RawVulnerability> filterToSet(Set<RawVulnerability> set, Predicate<RawVulnerability> filter) {
        return set.stream().filter(filter).collect(Collectors.toSet());
    }

    private static Set<RawVulnerability> filterBySourceType(Set<RawVulnerability> set, SourceType st) {
        return filterToSet(set, rv->rv.getSourceType()==st);
    }

    private static Set<RawVulnerability> filterByFilterStatus(Set<RawVulnerability> set, FilterStatus fs) {
        return filterToSet(set, rv->rv.getFilterStatus()==fs);
    }

    private static List<RawVulnerability> sortByPrio(Collection<RawVulnerability> vulns) {
        return vulns.stream().sorted(Comparator.comparingInt(RawVulnerability::getSourcePriority).reversed()).collect(Collectors.toList());
    }

}
