package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.*;

/**
 * abstract representation of a filtering stage
 */
public abstract class Filter {
    /**
     * Checks to see if a RawVulnerability contains a well-formed description
     * @param rawVuln A RawVulnerability in need of verification
     * @return true iff the RawVulnerability is well-formed
     */
    public abstract boolean passesFilter(RawVulnerability rawVuln);

    /**
     * Runs each RawVulnerability through the filter, removing the rejects from the list and returning the rejects as their own list
     * @param rawVulns A list of RawVulnerabilities in need of description verification
     * @return List of rejected RawVulnerabilities
     */
    public Set<RawVulnerability> filterAll(Set<RawVulnerability> rawVulns) {
        Set<RawVulnerability> removed = new HashSet<>();
        Iterator<RawVulnerability> iterator = rawVulns.iterator();
        while (iterator.hasNext()) {
            RawVulnerability vuln = iterator.next();
            if (!passesFilter(vuln)) {
                iterator.remove();
                removed.add(vuln);
            }
        }
        return removed;
    }
}
