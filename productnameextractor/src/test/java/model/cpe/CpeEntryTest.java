package model.cpe;

import edu.rit.se.nvip.model.cpe.CpeEntry;
import org.junit.Test;
import static org.junit.Assert.*;

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