package model.cpe;

import edu.rit.se.nvip.model.cpe.CpeEntry;
import edu.rit.se.nvip.model.cpe.CpeGroup;
import org.junit.Test;
import static org.junit.Assert.*;

import java.util.HashMap;
public class CpeGroupTest {

    @Test
    public void testGettersAndConstructor() {
        CpeEntry entry1 = new CpeEntry("Title 1", "1.0", "update", "cpeID1", "platform");
        CpeEntry entry2 = new CpeEntry("Title 2", "2.0", "update", "cpeID2", "platform");
        HashMap<String, CpeEntry> versions = new HashMap<>();
        versions.put(entry1.getVersion(), entry1);
        versions.put(entry2.getVersion(), entry2);

        CpeGroup group = new CpeGroup("Vendor", "Product", "Common Title", versions);

        // Test getters
        assertEquals("Vendor", group.getVendor());
        assertEquals("Product", group.getProduct());
        assertEquals("Vendor:Product", group.getGroupID());
        assertEquals("Common Title", group.getCommonTitle());
        assertEquals(versions, group.getVersions());
    }

    @Test
    public void testAddVersion() {
        CpeGroup group = new CpeGroup("Vendor", "Product");

        // Add a version to the group
        CpeEntry entry1 = new CpeEntry("Title 1", "1.0", "update", "cpeID1", "platform");
        group.addVersion(entry1);

        // Test that the version is added to the group's versions
        assertEquals(1, group.getVersions().size());
        assertTrue(group.getVersions().containsKey(entry1.getVersion()));
        assertEquals(entry1, group.getVersions().get(entry1.getVersion()));

        // Add another version to the group
        CpeEntry entry2 = new CpeEntry("Title 2", "2.0", "update", "cpeID2", "platform");
        group.addVersion(entry2);

        // Test that the second version is added to the group's versions
        assertEquals(2, group.getVersions().size());
        assertTrue(group.getVersions().containsKey(entry2.getVersion()));
        assertEquals(entry2, group.getVersions().get(entry2.getVersion()));

        // Test that the common title is updated correctly
        assertEquals("Title", group.getCommonTitle());

        // Add a version with a different common title
        CpeEntry entry3 = new CpeEntry("Different Title", "3.0", "update", "cpeID3", "platform");
        group.addVersion(entry3);

        // Test that the third version is added to the group's versions
        assertEquals(3, group.getVersions().size());
        assertTrue(group.getVersions().containsKey(entry3.getVersion()));
        assertEquals(entry3, group.getVersions().get(entry3.getVersion()));

        // Test that the common title is updated correctly
        assertEquals("Title", group.getCommonTitle());
    }

    @Test
    public void testEquals() {
        CpeEntry entry1 = new CpeEntry("Title 1", "1.0", "update", "cpeID1", "platform");
        CpeEntry entry2 = new CpeEntry("Title 2", "2.0", "update", "cpeID2", "platform");
        HashMap<String, CpeEntry> versions1 = new HashMap<>();
        versions1.put(entry1.getVersion(), entry1);
        versions1.put(entry2.getVersion(), entry2);

        CpeEntry entry3 = new CpeEntry("Title 3", "3.0", "update", "cpeID3", "platform");
        HashMap<String, CpeEntry> versions2 = new HashMap<>();
        versions2.put(entry3.getVersion(), entry3);

        CpeGroup group1 = new CpeGroup("Vendor", "Product", "Common Title", versions1);
        CpeGroup group2 = new CpeGroup("Vendor", "Product", "Common Title", versions1);
        CpeGroup group3 = new CpeGroup("Different Vendor", "Different Product", "Different Title", versions2);

        // Test equality between two CpeGroup instances with the same values
        assertEquals(group1, group2);

        // Test inequality between two CpeGroup instances with different values
        assertNotEquals(group1, group3);
    }

    @Test
    public void testHashCode() {
        CpeEntry entry1 = new CpeEntry("Title 1", "1.0", "update", "cpeID1", "platform");
        CpeEntry entry2 = new CpeEntry("Title 2", "2.0", "update", "cpeID2", "platform");
        HashMap<String, CpeEntry> versions1 = new HashMap<>();
        versions1.put(entry1.getVersion(), entry1);
        versions1.put(entry2.getVersion(), entry2);

        CpeEntry entry3 = new CpeEntry("Title 3", "3.0", "update", "cpeID3", "platform");
        HashMap<String, CpeEntry> versions2 = new HashMap<>();
        versions2.put(entry3.getVersion(), entry3);

        CpeGroup group1 = new CpeGroup("Vendor", "Product", "Common Title", versions1);
        CpeGroup group2 = new CpeGroup("Vendor", "Product", "Common Title", versions1);
        CpeGroup group3 = new CpeGroup("Different Vendor", "Different Product", "Different Title", versions2);

        // Test that two equal CpeGroup instances have the same hash code
        assertEquals(group1.hashCode(), group2.hashCode());

        // Test that two different CpeGroup instances have different hash codes
        assertNotEquals(group1.hashCode(), group3.hashCode());
    }
}