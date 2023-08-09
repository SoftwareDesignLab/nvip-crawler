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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EnglishDescriptionFilterTest {
    @Test
    void passesFilter() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "test cve-id",
                "test description",
                null,
                null,
                null,
                null);
        Filter filter = new EnglishDescriptionFilter();
        assertTrue(filter.passesFilter(rawVuln));
    }

    @Test
    void failsFilterSingleChar() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "test cve-id",
                "空",
                null,
                null,
                null,
                null);
        Filter filter = new EnglishDescriptionFilter();
        assertFalse(filter.passesFilter(rawVuln));
    }

    @Test
    void failsFilter() {
        RawVulnerability rawVuln = new RawVulnerability(1,
                "test cve-id",
                "s-bot 3 负责人： 仰望星空 CVE-2023-2650 主要 CVE/FIXED sig/security #I79L4T opengauss-bot 5 负责人： " +
                        "蒋宏博 CVE-2023-28322 CVE/FIXED sig/security #I740L7 majun-bot 5 负责人： 蒋宏博 CVE-2023-29469 CVE/FI" +
                        "XED sig/security #I6UW9J opengauss-bot 5 负责人： 蒋宏博 CVE-2023-28484 CVE/FIXED sig/security #I6UW7" +
                        "O opengauss-bot 5 负责人： 蒋宏博 CVE-2023-0465 CVE/FIXED sig/security #I6R5AU opengauss-bot 5 负责人：" +
                        " 蒋宏博 CVE-2023-0464 CVE/FIXED sig/security #I6PDB7 opengauss-bot 9 负责人： 蒋宏博 CVE-2022-4899 CVE/" +
                        "FIXED sig/security #I6ONEJ opengauss-bot 6 负责人： 蒋宏博 CVE-2023-27534 CVE/FIXED sig/security #I6ON" +
                        "EI opengauss-bot 7 负责人： buter CVE-2023-27533 CV",
                null,
                null,
                null,
                null);
        Filter filter = new EnglishDescriptionFilter();
        assertFalse(filter.passesFilter(rawVuln));
    }
}