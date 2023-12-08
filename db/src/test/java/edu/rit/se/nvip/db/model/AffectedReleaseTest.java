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
 * Tests for AffectedRelease Model
 */
public class AffectedReleaseTest {
    @Test
    public void testAffectedRelease() {
        AffectedRelease obj = new AffectedRelease(0, "cve_id", "cpe", "release_date", "version");

        assertEquals(obj.getId(), 0);
        assertEquals(obj.getCveId(), "cve_id");
        assertEquals(obj.getCpe(), "cpe");
        assertEquals(obj.getReleaseDate(), "release_date");
        assertEquals(obj.getVersion(), "version");

        obj.setCveId("new_cve_id");
        obj.setReleaseDate("new_release_date");
        obj.setVersion("new_version");

        assertEquals(obj.getCveId(), "new_cve_id");
        assertEquals(obj.getReleaseDate(), "new_release_date");
        assertEquals(obj.getVersion(), "new_version");
    }

    @Test
    public void testAffectedReleaseToString() {
        AffectedRelease obj = new AffectedRelease(0, "cve_id", "cpe", "release_date", "version");
        String ref = "AffectedRelease(id=0, cveId=" + "cve_id" + ", cpe=" + "cpe" + ", releaseDate=" + "release_date" + ", version=" + "version" + ")";
        assertEquals(obj.toString(), ref);
    }

    @Test
    public void testAffectedReleaseEquals() {
        AffectedRelease obj1 = new AffectedRelease(0, "cve", "cpe", "release_date", "version");
        AffectedRelease obj2 = new AffectedRelease("cpe2", "release_date", "version");
        AffectedRelease obj3 = new AffectedRelease(obj1);

        boolean equals = obj1.equals("test");
        assertFalse(equals);

        equals = obj1.equals(obj2);
        assertFalse(equals);

        equals = obj1.equals(obj3);
        assertTrue(equals);
    }
}