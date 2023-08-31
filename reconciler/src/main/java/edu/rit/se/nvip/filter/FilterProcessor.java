package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.*;

public class FilterProcessor {

    public Map<RawVulnerability, FilterResult> runFilters(Set<RawVulnerability> newVulns, FilterChain filterChain) {
        Map<RawVulnerability, FilterResult> out = new HashMap<>();
        newVulns.forEach(v->out.put(v, filterChain.applyFilters(v)));
        return out;
    }

    public Map<RawVulnerability, FilterResult> runFiltersOptimally(Set<RawVulnerability> newVulns, FilterChain filterChain) {
        return runFiltersOptimally(newVulns, new HashSet<>(), filterChain);
    }

    private Map<RawVulnerability, FilterResult> runFiltersOptimally(Set<RawVulnerability> newVulns, Set<RawVulnerability> existingVulns, FilterChain filterChain) {
        Map<RawVulnerability, RawVulnerability> vulnToRep = buildEquivalenceClasses(newVulns, existingVulns);
        Map<RawVulnerability, FilterResult> vulnToStatus = new HashMap<>();
        Map<RawVulnerability, FilterResult> repResultCache = new HashMap<>();

        int highestPrioPassing = existingVulns.stream()
                .filter(v->v.getFilterStatus() == FilterStatus.PASSED)
                .map(RawVulnerability::getSourcePriority)
                .max(Integer::compareTo).orElse(-1);
        // make a list of new vulns sorted by priority, highest first
        List<RawVulnerability> sortedList = new ArrayList<>(newVulns);
        sortedList.sort(Comparator.comparingInt(RawVulnerability::getSourcePriority).reversed());

        for (RawVulnerability vuln : sortedList) {
            // if we've already seen a passing vuln of higher priority, don't bother running filters
            if (vuln.getSourcePriority() < highestPrioPassing) {
                vulnToStatus.put(vuln, new FilterResult(FilterStatus.UNEVALUATED, null));
                continue;
            }
            RawVulnerability rep = vulnToRep.getOrDefault(vuln, vuln);
            // if the EC rep has already been processed and cached, we can use its result
            // existing in the cache map means rep is in newVulns and appeared in an earlier iteration
            // this means no update needs to be made to highestPrioPassing
            if (repResultCache.containsKey(rep)) {
                vulnToStatus.put(vuln, repResultCache.get(rep));
                continue;
            }
            // if the EC representative isn't new, we can use its prior filter result
            // if this is the first "passing" loop iteration, then highestPrioPassing should obviously be set to vuln.getSourcePriority()
            // if this is not the first "passing" loop iteration, vuln.prio must already be equal to highestPrioPassing, so there's no harm in updating
            if (existingVulns.contains(rep)) {
                vulnToStatus.put(vuln, new FilterResult(rep.getFilterStatus(), null));
                if (rep.getFilterStatus() == FilterStatus.PASSED) {
                    highestPrioPassing = vuln.getSourcePriority();
                }
                continue;
            }
            // if we're here, vuln's EC rep hasn't been seen yet and the EC rep isn't already existing from a prior run
            // this means there are no prior results we can appeal to, so we run the filters and cache the result
            FilterResult result = filterChain.applyFilters(vuln); // doesn't matter if we run on vuln or rep, since by definition they are equivalent under filtering
            repResultCache.put(rep, result);
            vulnToStatus.put(vuln, result);
            if (result.getStatus() == FilterStatus.PASSED) {
                // since the outer loop is going through a reverse sorted list, vuln must have prio >= rep
                // if vuln.prio < highestPrioPassing, then we would have skipped it so we wouldn't be here, so vuln.prio >= highestPrioPassing
                // thus we should set highestPrioPassing to vuln.prio
                highestPrioPassing = vuln.getSourcePriority();
            }
        }
        return vulnToStatus;
    }

    private Map<RawVulnerability, RawVulnerability> buildEquivalenceClasses(Set<RawVulnerability> newVulns, Set<RawVulnerability> existingVulns) {
        Map<RawVulnerability, RawVulnerability> equivClassRep = new HashMap<>();
        for (RawVulnerability newVuln : newVulns) {
            // might have been found as a match for a previous vuln and thus already added
            if (equivClassRep.containsKey(newVuln)) {
                continue;
            }
            // find all matching existing vulns
            Set<RawVulnerability> equivVulns = new HashSet<>();
            RawVulnerability rep = newVuln;
            for (RawVulnerability ex : existingVulns) {
                if (newVuln.equivalentUnderFiltering(ex)) {
                    rep = ex;
                    break;
                }
            }
            for (RawVulnerability otherNew : newVulns) {
                if (newVuln.equivalentUnderFiltering(otherNew)) {
                    equivVulns.add(otherNew);
                }
            }
            // set rep (either vuln or an existing vuln) as the representative for all (new) matches
            for (RawVulnerability eq : equivVulns) {
                equivClassRep.put(eq, rep);
            }
        }
        return equivClassRep;
    }
}
