package model.cpe;

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

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for CpeEntry class
 *
 * @author Richard Sawh
 */
public class CpeEntryTest {

    @Test
    public void testGettersAndConstructor() {
        CpeEntry entry = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");

        // Test getters
        assertEquals("Title", entry.getTitle());
        assertEquals("1.0", entry.getVersion());
        assertEquals("update", entry.getUpdate());
        assertEquals("cpeID", entry.getCpeID());
        assertEquals("platform", entry.getPlatform());
    }

    @Test
    public void testSetters() {
        CpeEntry entry = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");

        // Test setters
        entry.setTitle("New Title");
        entry.setVersion("2.0");
        entry.setUpdate("new update");
        entry.setCpeID("new cpeID");
        entry.setPlatform("new platform");

        assertEquals("New Title", entry.getTitle());
        assertEquals("2.0", entry.getVersion());
        assertEquals("new update", entry.getUpdate());
        assertEquals("new cpeID", entry.getCpeID());
        assertEquals("new platform", entry.getPlatform());
    }

    @Test
    public void testEquals() {
        CpeEntry entry1 = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");
        CpeEntry entry2 = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");
        CpeEntry entry3 = new CpeEntry("Different Title", "2.0", "update", "cpeID", "platform");

        // Test equality between two CpeEntry instances with the same values
        assertEquals(entry1, entry2);

        // Test inequality between two CpeEntry instances with different values
        assertNotEquals(entry1, entry3);
    }

    @Test
    public void testHashCode() {
        CpeEntry entry1 = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");
        CpeEntry entry2 = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");
        CpeEntry entry3 = new CpeEntry("Different Title", "2.0", "update", "cpeID", "platform");

        // Test that two equal CpeEntry instances have the same hash code
        assertEquals(entry1.hashCode(), entry2.hashCode());

        // Test that two different CpeEntry instances have different hash codes
        assertNotEquals(entry1.hashCode(), entry3.hashCode());
    }

    @Test
    public void testToString() {
        CpeEntry entry = new CpeEntry("Title", "1.0", "update", "cpeID", "platform");

        String expected = "CpeEntry [title=Title, cpeID=cpeID]";
        assertEquals(expected, entry.toString());
    }
}