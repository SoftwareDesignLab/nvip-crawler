/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

/**
 * abstract representation of a filtering stage
 */
public abstract class Filter {

    protected final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    /**
     * Checks to see if a RawVulnerability contains a well-formed description. Implementations must not alter the input
     * @param rawVuln A RawVulnerability in need of verification
     * @return true iff the RawVulnerability is well-formed
     */
    public abstract boolean passesFilter(RawVulnerability rawVuln);

    /**
     * Runs each RawVulnerability through the filter and updates their FilterStatus accordingly
     * @param rawVulns A list of RawVulnerabilities in need of description verification
     * @return Set of rejected RawVulnerabilities
     */
    public void filterAll(Set<RawVulnerability> rawVulns) {
        for (RawVulnerability vuln : rawVulns) {
            updateFilterStatus(vuln);
        }
    }

    public Set<RawVulnerability> filterAllAndSplit(Set<RawVulnerability> rawVulns) {
        filterAll(rawVulns);
        Set<RawVulnerability> rejects = rawVulns.stream().filter(v -> v.getFilterStatus() == RawVulnerability.FilterStatus.FAILED).collect(Collectors.toSet());
        rawVulns.removeAll(rejects);
        return rejects;
    }

    protected void updateFilterStatus(RawVulnerability vuln) {
        // already failed earlier in the pipeline? don't bother filtering any more
        if (vuln.getFilterStatus() == RawVulnerability.FilterStatus.FAILED) {
            return;
        }
        // users are always right
        if (vuln.getSourceType() == RawVulnerability.SourceType.USER) {
            vuln.setFilterStatus(RawVulnerability.FilterStatus.PASSED);
            return;
        }
        if (passesFilter(vuln)) {
            vuln.setFilterStatus(RawVulnerability.FilterStatus.PASSED);
        } else {
            vuln.setFilterStatus(RawVulnerability.FilterStatus.FAILED);
        }
    }
}
