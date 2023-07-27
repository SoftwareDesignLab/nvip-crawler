package model;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.Test;
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