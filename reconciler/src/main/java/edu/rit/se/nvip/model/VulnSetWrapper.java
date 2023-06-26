package edu.rit.se.nvip.model;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class VulnSetWrapper {
    private final Set<RawVulnerability> vulns;

    public VulnSetWrapper(Set<RawVulnerability> vulns) {
        this.vulns = vulns;
    }

    public boolean hasPassedHighPrio() {
        for (RawVulnerability v : vulns) {
            if (v.getFilterStatus() == RawVulnerability.FilterStatus.PASSED && v.isHighPriority()) {
                return true;
            }
        }
        return false;
    }

    public Set<RawVulnerability> firstFilterWave() {
        // first wave of filtering will be any high priority sources that haven't been evaluated yet
        return vulns.stream().filter(v -> !v.isFiltered()).filter(RawVulnerability::isHighPriority).collect(Collectors.toSet());
    }

    public Set<RawVulnerability> secondFilterWave() {
        if (hasPassedHighPrio()) {
            // no need for a second wave
            return new HashSet<>();
        }
        // all the high prio sources failed, release the second wave of low prio sources
        return vulns.stream().filter(v -> !v.isFiltered()).collect(Collectors.toSet());
    }

    public int setNewToUneval() {
        int out = 0;
        for (RawVulnerability v : vulns) {
            if (v.getFilterStatus() == RawVulnerability.FilterStatus.NEW) {
                out++;
                v.setFilterStatus(RawVulnerability.FilterStatus.UNEVALUATED);
            }
        }
        return out;
    }

    public Set<RawVulnerability> toUpdate() {
        return vulns.stream().filter(RawVulnerability::filterStatusChanged).collect(Collectors.toSet());
    }

    public Set<RawVulnerability> toReconcile() {
        // if a vuln was changed, it was unfiltered before and thus hasn't been considered for prior reconciliation
        // then take the changed ones and pick out the passed vulns
        // don't need to worry about prio here because nothing gets filtered in this run that we don't want to use
        return toUpdate().stream().filter(v -> v.getFilterStatus() == RawVulnerability.FilterStatus.PASSED).collect(Collectors.toSet());
    }
}
