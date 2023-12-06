/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import edu.rit.se.nvip.reconciler.filter.Filter;
import edu.rit.se.nvip.reconciler.filter.MultipleCveDescriptionsFilter;
import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MultipleCveDescriptionsFilterTest {
    @Test
    void passesFilter() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "CVE-2023-0609",
                "test description",
                null,
                null,
                null,
                null);

        Filter filter = new MultipleCveDescriptionsFilter();
        assertTrue(filter.passesFilter(rawVuln));
    }

    @Test
    void failsFilter() {
        String testDesc1 = "CVE-2022-39199, GHSA-6cqj-6969-p57x";
        String testDesc2 = "CVE-2020-8945, GHSA-m6wg-2mwg-4rfq";
        String testDesc3 = "CVE-2022-24968, GHSA-h289-x5wc-xcv8, and 1 more";
        String testDesc4 = "CVE-2020-7711, CVE-2020-7731, and 3 more";
        String testDesc5 = "CVE-2022-26945, CVE-2022-30321, and 6 more";

        RawVulnerability rawVuln1 = new RawVulnerability(1, "testID", testDesc1, null, null, null, null);
        RawVulnerability rawVuln2 = new RawVulnerability(2, "testID", testDesc2, null, null, null, null);
        RawVulnerability rawVuln3 = new RawVulnerability(3, "testID", testDesc3, null, null, null, null);
        RawVulnerability rawVuln4 = new RawVulnerability(4, "testID", testDesc4, null, null, null, null);
        RawVulnerability rawVuln5 = new RawVulnerability(5, "testID", testDesc5, null, null, null, null);

        Filter filter = new MultipleCveDescriptionsFilter();

        assertFalse(filter.passesFilter(rawVuln1));
        assertFalse(filter.passesFilter(rawVuln2));
        assertFalse(filter.passesFilter(rawVuln3));
        assertFalse(filter.passesFilter(rawVuln4));
        assertFalse(filter.passesFilter(rawVuln5));
    }
}