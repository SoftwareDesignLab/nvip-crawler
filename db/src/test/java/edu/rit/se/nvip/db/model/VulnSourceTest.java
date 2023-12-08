/**
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
*/

package edu.rit.se.nvip.db.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for VulnSource Model
 */
public class VulnSourceTest {
    @Test
    public void testVulnSource() {
        VulnSource obj = new VulnSource("cve_id", "url");

        assertEquals(obj.getCveId(), "cve_id");
        assertEquals(obj.getUrl(), "url");

        obj.setCveId("new_cve_id");
        obj.setUrl("new_url");

        assertEquals(obj.getCveId(), "new_cve_id");
        assertEquals(obj.getUrl(), "new_url");
    }

    @Test
    public void testEquals() {
        String url = "https://talosintelligence.com/vulnerability_reports/TALOS-2016-0036";
        VulnSource vuln = new VulnSource("", url);
        VulnSource vuln2 = new VulnSource("", url);

        boolean ok = vuln.equals(vuln2);
        assertTrue(ok);

        vuln = new VulnSource("", url);
        vuln2 = new VulnSource("", url + "X");
        ok = vuln.equals(vuln2);
        assertFalse(ok);

        vuln2 = null;
        ok = vuln.equals(vuln2);
        assertFalse(ok);

        ok = vuln.equals("test");
        assertFalse(ok);
    }
}