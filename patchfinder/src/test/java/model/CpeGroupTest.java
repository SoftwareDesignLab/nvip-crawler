package model;

import org.junit.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;

public class CpeGroupTest {

    @Test
    public void testCpeGroupConstructorAndGetters() {
        String vendor = "vendor";
        String product = "product";

        CpeGroup cpeGroup = new CpeGroup(vendor, product);

        assertEquals(vendor, cpeGroup.getVendor());
        assertEquals(product, cpeGroup.getProduct());
        assertEquals(vendor + ":" + product, cpeGroup.getGroupID());
        assertNull(cpeGroup.getCommonTitle());
        assertNotNull(cpeGroup.getVersions());
        assertEquals(0, cpeGroup.getVersionsCount());
    }

    @Test
    public void testCpeGroupAddVersion() {
        String vendor = "vendor";
        String product = "product";

        CpeGroup cpeGroup = new CpeGroup(vendor, product);

        assertEquals(0, cpeGroup.getVersionsCount());

        CpeEntry version1 = new CpeEntry("Title 1", "1.0", "", "cpe:/o:vendor:product:1.0", "");
        cpeGroup.addVersion(version1);

        assertEquals(1, cpeGroup.getVersionsCount());
        assertTrue(cpeGroup.getVersions().containsKey("1.0"));
        assertEquals(version1, cpeGroup.getVersions().get("1.0"));
        assertEquals("Title 1", cpeGroup.getCommonTitle());

        CpeEntry version2 = new CpeEntry("Title 2", "2.0", "", "cpe:/o:vendor:product:2.0", "");
        cpeGroup.addVersion(version2);

        assertEquals(2, cpeGroup.getVersionsCount());
        assertTrue(cpeGroup.getVersions().containsKey("2.0"));
        assertEquals(version2, cpeGroup.getVersions().get("2.0"));
        assertEquals("Title", cpeGroup.getCommonTitle());
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

    @Test
    public void testEquals() {
        // Create two instances of CpeGroup with the same property values
        CpeGroup group1 = new CpeGroup("Vendor", "Product");
        group1.addVersion(new CpeEntry("Title", "1.0", "Update1", "cpe-1234", "Platform"));

        CpeGroup group2 = new CpeGroup("Vendor", "Product");
        group2.addVersion(new CpeEntry("Title", "1.0", "Update1", "cpe-1234", "Platform"));

        // Verify that the two instances are equal
        assertTrue(group1.equals(group2));
        assertTrue(group2.equals(group1));
    }
}