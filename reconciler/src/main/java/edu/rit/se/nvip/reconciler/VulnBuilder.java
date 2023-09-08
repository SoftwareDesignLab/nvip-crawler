package edu.rit.se.nvip.reconciler;

import edu.rit.se.nvip.filter.FilterChain;
import edu.rit.se.nvip.filter.FilterResult;
import edu.rit.se.nvip.filter.FilterStatus;
import edu.rit.se.nvip.model.CompositeDescription;
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
    private String cveId;
    private CompositeVulnerability existing;
    private CompositeDescription existingDesc;
    Set<RawVulnerability> allSources;

    public VulnBuilder(String cveId, CompositeVulnerability existing, Set<RawVulnerability> allSources) {
        this.cveId = cveId;
        this.existing = existing;
        this.existingDesc = existing == null ? null : existing.getCompositeDescription();
        this.allSources = allSources;
    }

    public CompositeVulnerability filterAndBuild(FilterChain filterChain, Reconciler reconciler) {
        Set<RawVulnerability> newPassedSources = runFiltersOnScrapedSources(filterChain);
        CompositeDescription desc = reconciler.reconcile(cveId, existingDesc, newPassedSources);
        CompositeVulnerability out = new CompositeVulnerability(desc, allSources);
        if (existing == null) {
            out.setRecStatus(CompositeVulnerability.ReconciliationStatus.NEW);
        } else if (existingDesc.equals(desc)) {
            // that equals call should be checking if the description strings are equal and the buildstrings are equal up to order
            // technically the compvuln's date fields might have been changed by this whole process, but that doesn't matter for this status
            out.setRecStatus(CompositeVulnerability.ReconciliationStatus.UNCHANGED);
        } else {
            out.setRecStatus(CompositeVulnerability.ReconciliationStatus.UPDATED);
        }
        return out;
    }

    public CompositeVulnerability overrideWithUser() throws VulnBuilderException {
        if (existing == null) {
            throw new VulnBuilderException("The existing composite vulnerability is null and thus cannot be overridden");
        }
        // pull out the NEW raw vulnerabilities created from a USER
        // in a normal scenario there should only be 1, but it's possible 2 users make edits close enough in time that
        // the second one ends up in the db before the reconciler can process the first
        List<RawVulnerability> newUserSources = allSources.stream()
                .filter(v->v.getSourceType()==SourceType.USER && v.getFilterStatus() == FilterStatus.NEW)
                .sorted(Comparator.comparing(RawVulnerability::getCreateDate))
                .collect(Collectors.toList());
        if (newUserSources.size() == 0) {
            throw new VulnBuilderException("No new user sources were found");
        }
        if (newUserSources.size() > 1) {
            logger.warn("Multiple new user sources were found, the most recent one will be applied");
        }
        // mark all new user sources as passed because we trust our users
        newUserSources.forEach(v->v.setFilterStatus(FilterStatus.PASSED));
        // take the newest one by creation date and use it as an override
        RawVulnerability newestUserSource = newUserSources.get(newUserSources.size()-1);
        CompositeDescription userDesc = existingDesc.duplicate();
        userDesc.addUserSource(newestUserSource);
        CompositeVulnerability out = new CompositeVulnerability(userDesc, allSources);
        out.setRecStatus(CompositeVulnerability.ReconciliationStatus.UPDATED);
        return out;
    }

    private Set<RawVulnerability> runFiltersOnScrapedSources(FilterChain filterChain) {
        Set<RawVulnerability> newSources = filterByFilterStatus(allSources, FilterStatus.NEW);
        Set<RawVulnerability> existingSources = filterToSet(allSources, rv->!newSources.contains(rv));
        newSources.removeAll(filterBySourceType(newSources, SourceType.USER)); // not our problem to deal with new user sources
        Map<RawVulnerability, FilterResult> newSourceToFilterStatus = filterChain.runFilters(newSources, existingSources);
        sortByPrio(newSourceToFilterStatus.keySet()).forEach(rv->updateFilterStatus(rv, newSourceToFilterStatus.get(rv)));
        return filterByFilterStatus(newSourceToFilterStatus.keySet(), FilterStatus.PASSED);
    }

    private void updateFilterStatus(RawVulnerability rv, FilterResult fr) {
        switch(fr.getStatus()) {
            case UNEVALUATED:
                logger.info("CVE {} from source {} with vuln_id {} was skipped by NVIP's filtering system due to being a low priority source",
                        rv.getCveId(), rv.getSourceUrl(), rv.getId());
            case PASSED:
                logger.info("CVE {} from source {} with vuln_id {} passed all NVIP quality filters",
                        rv.getCveId(), rv.getSourceUrl(), rv.getId());
            case FAILED:
                if (fr.getFailedAt() == null) {
                    logger.info("CVE {} from source {} with vuln_id {} was rejected by NVIP's filters because its data is equivalent to a previously rejected source",
                            rv.getCveId(), rv.getSourceUrl(), rv.getId());
                } else {
                    logger.info("CVE {} from source {} with vuln_id {} was rejected by NVIP's filters at the {} stage.",
                            rv.getCveId(), rv.getSourceUrl(), rv.getId(), fr.getFailedAt());
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

    public static class VulnBuilderException extends Exception {
        public VulnBuilderException(String message) {
            super();
        }
    }

}
