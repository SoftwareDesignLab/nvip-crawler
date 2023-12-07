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

package edu.rit.se.nvip.model;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import edu.rit.se.nvip.db.model.RawVulnerability;

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
