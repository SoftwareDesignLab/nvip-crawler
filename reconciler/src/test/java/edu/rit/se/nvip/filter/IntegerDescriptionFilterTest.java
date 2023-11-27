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
import edu.rit.se.nvip.reconciler.filter.Filter;
import edu.rit.se.nvip.reconciler.filter.IntegerDescriptionFilter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IntegerDescriptionFilterTest {

    @Test
    void passesFilter() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "CVE-2023-0609",
                "test description",
                null,
                null,
                null,
                null);

        Filter filter = new IntegerDescriptionFilter();
        assertTrue(filter.passesFilter(rawVuln));
    }

    @Test
    void failsFilter() {
        RawVulnerability rawVuln1 = new RawVulnerability(1,
                "CVE-2023-0609",
                "1",
                null,
                null,
                null,
                null);

        RawVulnerability rawVuln2 = new RawVulnerability(2,
                "CVE-2023-0609",
                "2     ",
                null,
                null,
                null,
                null);

        RawVulnerability rawVuln3 = new RawVulnerability(3,
                "CVE-2023-0609",
                "\n300\n",
                null,
                null,
                null,
                null);

        Filter filter = new IntegerDescriptionFilter();

        assertFalse(filter.passesFilter(rawVuln1));
        assertFalse(filter.passesFilter(rawVuln2));
        assertFalse(filter.passesFilter(rawVuln3));
    }
}