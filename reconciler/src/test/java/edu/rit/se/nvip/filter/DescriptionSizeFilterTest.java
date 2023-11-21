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
import edu.rit.se.nvip.reconciler.filter.DescriptionSizeFilter;
import edu.rit.se.nvip.reconciler.filter.Filter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DescriptionSizeFilterTest {

    @Test
    void passesFilter() {
        //Tests description with normal, regular string as a description
        RawVulnerability rawVuln1 = new RawVulnerability(1,
                "CVE-2023-0609",
                "test description",
                null,
                null,
                null,
                null);

        //Tests description with max length string
        StringBuilder sb2 = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb2.append("a");
        }
        String testDesc2 = sb2.toString();
        RawVulnerability rawVuln2 = new RawVulnerability(2,
                "CVE-2023-0609",
                testDesc2,
                null,
                null,
                null,
                null);

        //Tests that empty strings of >1000 size still passes filter
        StringBuilder sb3 = new StringBuilder();
        for (int i = 0; i < 1001; i++) {
            sb3.append(" ");
        }
        String testDesc3 = sb3.toString();
        RawVulnerability rawVuln3 = new RawVulnerability(3,
                "CVE-2023-0609",
                testDesc3,
                null,
                null,
                null,
                null);

        Filter filter = new DescriptionSizeFilter();

        assertTrue(filter.passesFilter(rawVuln1));
        assertTrue(filter.passesFilter(rawVuln2));
        assertTrue(filter.passesFilter(rawVuln3));
    }

    @Test
    void failsFilter() {
        //Tests description with max length string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1001; i++) {
            sb.append("a");
        }
        String testDesc = sb.toString();
        RawVulnerability rawVuln = new RawVulnerability(1,
                "CVE-2023-0609",
                testDesc,
                null,
                null,
                null,
                null);

        Filter filter = new DescriptionSizeFilter();

        assertFalse(filter.passesFilter(rawVuln));
    }
}