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

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CpeEntry class
 *
 * @author Richard Sawh
 */
public class CpeEntryTest {

    @Test
    public void testCpeEntryConstructorAndGetters() {
        String title = "Sample Title";
        String version = "1.0";
        String update = "2";
        String cpeID = "cpe:/o:vendor:product:version:update";
        String platform = "Windows";

        CpeEntry cpeEntry = new CpeEntry(title, version, update, cpeID, platform);

        assertEquals(title, cpeEntry.getTitle());
        assertEquals(version, cpeEntry.getVersion());
        assertEquals(update, cpeEntry.getUpdate());
        assertEquals(cpeID, cpeEntry.getCpeID());
        assertEquals(platform, cpeEntry.getPlatform());
    }

    @Test
    public void testCpeEntryConstructorForProductNameExtractor() {
        String title = "Sample Title";
        String version = "1.0";
        String cpeID = "cpe:/o:vendor:product:version:update";

        CpeEntry cpeEntry = new CpeEntry(title, version, cpeID);

        assertEquals(title, cpeEntry.getTitle());
        assertEquals(version, cpeEntry.getVersion());
        assertEquals("", cpeEntry.getUpdate());
        assertEquals(cpeID, cpeEntry.getCpeID());
        assertEquals("", cpeEntry.getPlatform());
    }

    @Test
    public void testCpeEntrySetters() {
        String title = "Sample Title";
        String version = "1.0";
        String update = "2";
        String cpeID = "cpe:/o:vendor:product:version:update";
        String platform = "Windows";

        CpeEntry cpeEntry = new CpeEntry("", "", "", "", "");

        cpeEntry.setTitle(title);
        cpeEntry.setVersion(version);
        cpeEntry.setUpdate(update);
        cpeEntry.setCpeID(cpeID);
        cpeEntry.setPlatform(platform);

        assertEquals(title, cpeEntry.getTitle());
        assertEquals(version, cpeEntry.getVersion());
        assertEquals(update, cpeEntry.getUpdate());
        assertEquals(cpeID, cpeEntry.getCpeID());
        assertEquals(platform, cpeEntry.getPlatform());
    }

    @Test
    public void testCpeEntryHashCodeAndEquals() {
        CpeEntry cpeEntry1 = new CpeEntry("Title", "1.0", "2", "cpe:/o:vendor:product:version:update", "Windows");
        CpeEntry cpeEntry2 = new CpeEntry("Title", "1.0", "2", "cpe:/o:vendor:product:version:update", "Windows");
        CpeEntry cpeEntry3 = new CpeEntry("Title", "1.0", "3", "cpe:/o:vendor:product:version:update", "Windows");

        assertEquals(cpeEntry1, cpeEntry2);
        assertNotEquals(cpeEntry1, cpeEntry3);
    }

    @Test
    public void testCpeEntryToString() {
        String title = "Sample Title";
        String cpeID = "cpe:/o:vendor:product:version:update";

        CpeEntry cpeEntry = new CpeEntry(title, "", cpeID);

        assertEquals("CpeEntry [title=" + title + ", cpeID=" + cpeID + "]", cpeEntry.toString());
    }

    @Test
    public void testHashCode() {
        // Create two instances of CpeEntry with the same property values
        CpeEntry obj1 = new CpeEntry("Sample Title", "1.0", "Update1", "cpe-1234", "Sample Platform");
        CpeEntry obj2 = new CpeEntry("Sample Title", "1.0", "Update1", "cpe-1234", "Sample Platform");

        // Verify that the hash codes of the two instances are equal
        assertEquals(obj1.hashCode(), obj2.hashCode());
    }
}