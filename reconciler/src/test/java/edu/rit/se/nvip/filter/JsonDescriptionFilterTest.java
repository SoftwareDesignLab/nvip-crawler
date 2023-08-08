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

import static org.junit.jupiter.api.Assertions.*;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

class JsonDescriptionFilterTest {
    @Test
    public void passesFilter() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "CVE-2017-7466",
                "test description",
                null,
                null,
                null,
                null);
        Filter filter = new JsonDescriptionFilter();
        assertTrue(filter.passesFilter(rawVuln));
    }

    @Test
    public void failsFilter() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "CVE-2017-7466",
                "le-CVE-2014-4660.json ansible-CVE-2014-4678.json ansible-CVE-2014-4966.json ansible-CVE-2014-4967.json ansible-CVE-2015-3908.json ansible-CVE-2015-6240.json ansible-CVE-2016-3096.json ansible-CVE-2016-8614.json ansible-CVE-2016-8628.json ansible-CVE-2016-8647.json ansible-CVE-2016-9587.json ansible-CVE-2017-7466.json ansible-CVE-2017-7481.json ansible-CVE-2017-7550.json ansible-CVE-2018-10855.json ansible-CVE-2018-10874.json ansible-CVE-2018-10875.json ansible-CVE-2018-16837.json ansible-CVE-2018-16859.json ansible-CVE-2018-16876.json ansible-CVE-2019-10156.json ansible-CVE-2019-10206.json ans",
                null,
                null,
                null,
                null);
        Filter filter = new JsonDescriptionFilter();
        assertFalse(filter.passesFilter(rawVuln));
    }
}