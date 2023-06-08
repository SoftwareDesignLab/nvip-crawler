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
     * @return Set of rejected RawVulnerabilities
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
