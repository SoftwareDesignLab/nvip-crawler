package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class FilterChain {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private final List<Filter> filterList;
    private final boolean optimizeWithCaching;
    private final boolean optimizeWithPriority;

    public FilterChain(List<Filter> filterList, boolean optimizeWithCaching, boolean optimizeWithPriority) {
        this.filterList = filterList;
        this.optimizeWithCaching = optimizeWithCaching;
        this.optimizeWithPriority = optimizeWithPriority;
    }

    public static List<Filter> localFilters() {
        List<Filter> filterList = new ArrayList<>();
        filterList.add(new BlankDescriptionFilter());
        filterList.add(new CveMatchesDescriptionFilter());
        filterList.add(new IntegerDescriptionFilter());
        filterList.add(new MultipleCveDescriptionsFilter());
        filterList.add(new DescriptionSizeFilter());
        return filterList;
    }

    public FilterResult applyFilters(RawVulnerability vuln) {
        for (Filter filter : this.filterList) {
            if (!filter.passesFilter(vuln)) {
                return new FilterResult(FilterStatus.FAILED, filter.getClass().getSimpleName());
            }
        }
        return new FilterResult(FilterStatus.PASSED, null);
    }

    public Map<RawVulnerability, FilterResult> runFilters(Set<RawVulnerability> newVulns) {
        if (this.optimizeWithCaching) {
            return this.runFiltersOptimally(newVulns, new HashSet<>());
        } else {
            return this.runFiltersNoCache(newVulns);
        }
    }

    public Map<RawVulnerability, FilterResult> runFilters(Set<RawVulnerability> newVulns, Set<RawVulnerability> existingVulns) {
        if (this.optimizeWithCaching) {
            return this.runFiltersOptimally(newVulns, existingVulns);
        } else {
            return this.runFiltersNoCache(newVulns);
        }
    }

    /**
     * Lazily runs every RawVulnerability through the filter chain without using cached results from filter-equivalent vulnerabilities.
     * This method does not alter the contents of newVulns nor does it alter the state of any RawVulnerability
     * @param newVulns A set of RawVulnerabilities to verify data (description) quality
     * @return A Map from RawVulnerability a FilterResult object, containing PASSED/FAILED and the first failing filter if applicable.
     */
    private Map<RawVulnerability, FilterResult> runFiltersNoCache(Set<RawVulnerability> newVulns) {
        Iterable<RawVulnerability> vulnColl = optimizeWithPriority ? sortByPriority(newVulns) : newVulns;
        Map<RawVulnerability, FilterResult> out = new HashMap<>();
        int highestPrioPassing = -1;
        for (RawVulnerability rv : vulnColl) {
            if (optimizeWithPriority && rv.getSourcePriority() < highestPrioPassing) {
                out.put(rv, new FilterResult(FilterStatus.UNEVALUATED, null));
                continue;
            }
            FilterResult result = this.applyFilters(rv);
            if (result.getStatus() == FilterStatus.PASSED) {
                highestPrioPassing = rv.getSourcePriority();
            }
            out.put(rv, result);
        }
        return out;
    }

    /**
     * Optimizes filter usage by splitting newVulns into equivalence classes under their equivalentUnderFiltering() method,
     * and either running once per equivalence class or using an equivalent existingVuln's filter status
     * @param newVulns A set of RawVulnerabilities to verify data (description) quality
     * @param existingVulns A set of previously analyzed RawVulnerabilities whose filterStatus we can trust as a cache
     * @return A Map from RawVulnerability a FilterResult object, containing PASSED/FAILED and the first failing filter if applicable.
     */
    private Map<RawVulnerability, FilterResult> runFiltersOptimally(Set<RawVulnerability> newVulns, Set<RawVulnerability> existingVulns) {
        Map<RawVulnerability, RawVulnerability> vulnToRep = buildEquivalenceClasses(newVulns, existingVulns);
        Map<RawVulnerability, FilterResult> vulnToStatus = new HashMap<>();
        Map<RawVulnerability, FilterResult> repResultCache = new HashMap<>();

        int highestPrioPassing = existingVulns.stream()
                .filter(v->v.getFilterStatus() == FilterStatus.PASSED)
                .map(RawVulnerability::getSourcePriority)
                .max(Integer::compareTo).orElse(-1);

        Iterable<RawVulnerability> newVulnColl = optimizeWithPriority ? sortByPriority(newVulns) : newVulns;

        for (RawVulnerability vuln : newVulnColl) {
            // if we've already seen a passing vuln of higher priority, don't bother running filters
            if (optimizeWithPriority && vuln.getSourcePriority() < highestPrioPassing) {
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
            FilterResult result = this.applyFilters(vuln); // doesn't matter if we run on vuln or rep, since by definition they are equivalent under filtering
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

    /**
     * Divides a set of RawVulnerabilities into equivalence classes by creating a map from each newVuln to a representative element.
     * @param newVulns The set to partition
     * @param existingVulns A set of previously filtered RawVulnerabilities we can use as a cache for filter results.
     * @return A map from each newVuln to a representative of its equivalence class, prioritizing an existingVuln should such a match exist
     */
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

    private static List<RawVulnerability> sortByPriority(Set<RawVulnerability> rawVulns) {
        List<RawVulnerability> out = new ArrayList<>(rawVulns);
        out.sort(Comparator.comparingInt(RawVulnerability::getSourcePriority).reversed());
        return out;
    }

}
