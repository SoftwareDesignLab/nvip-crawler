package model.cpe;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CpeEntryTest {

    @Test
    public void testCpeEntryEquals() {
        // Create two CpeEntry objects with the same properties
        CpeEntry entry1 = new CpeEntry("title", "version", "update", "cpeID", "platform");
        CpeEntry entry2 = new CpeEntry("title", "version", "update", "cpeID", "platform");

        // Assert that the two objects are equal
        Assertions.assertEquals(entry1, entry2);
    }

    @Test
    public void testCpeEntryNotEquals() {
        // Create two CpeEntry objects with different properties
        CpeEntry entry1 = new CpeEntry("title1", "version1", "update1", "cpeID1", "platform1");
        CpeEntry entry2 = new CpeEntry("title2", "version2", "update2", "cpeID2", "platform2");

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(entry1, entry2);
    }

    @Test
    public void testCpeEntryHashCode() {
        // Create two CpeEntry objects with the same properties
        CpeEntry entry1 = new CpeEntry("title", "version", "update", "cpeID", "platform");
        CpeEntry entry2 = new CpeEntry("title", "version", "update", "cpeID", "platform");

        // Assert that the hash codes of the two objects are equal
        Assertions.assertEquals(entry1.hashCode(), entry2.hashCode());
    }

    @Test
    public void testCpeEntryToString() {
        // Create a CpeEntry object
        CpeEntry entry = new CpeEntry("title", "version", "update", "cpeID", "platform");

        // Assert the string representation of the object
        Assertions.assertEquals("CpeEntry [title=title, cpeID=cpeID]", entry.toString());
    }
}
