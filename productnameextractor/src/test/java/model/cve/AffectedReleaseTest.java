package model.cve;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AffectedReleaseTest {

    @Test
    public void testEquals_WithEqualObjects() {
        // Create two AffectedRelease objects with different CVE ID and CPE
        AffectedRelease release1 = new AffectedRelease(1, "CVE-2023-1234", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");
        AffectedRelease release2 = new AffectedRelease(2, "CVE-2023-5678", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");

        // Assert that the two objects are not equal
        Assertions.assertFalse(release1.equals(release2));
    }

    @Test
    public void testEquals_WithDifferentObjects() {
        // Create two AffectedRelease objects with different CPEs
        AffectedRelease release1 = new AffectedRelease(1, "CVE-2023-1234", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");
        AffectedRelease release2 = new AffectedRelease(2, "CVE-2023-5678", "cpe:2.3:a:vulnerable_product:2.0", "2023-01-01", "2.0");

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(release1, release2);
    }

    @Test
    public void testEquals_WithNullObject() {
        // Create an AffectedRelease object
        AffectedRelease release = new AffectedRelease(1, "CVE-2023-1234", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");

        // Assert that the object is not equal to null
        Assertions.assertNotEquals(release, null);
    }

    @Test
    public void testGetPURL_WithUnknownProductName() {
        // Create an AffectedRelease object with an unknown product name
        AffectedRelease release = new AffectedRelease("cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");

        // Assert that getPURL returns null
        Assertions.assertNull(release.getPURL("UNKNOWN"));
    }

    @Test
    public void testGetSWID_WithUnknownProductName() {
        // Create an AffectedRelease object with an unknown product name
        AffectedRelease release = new AffectedRelease("cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");

        // Assert that getSWID returns null
        Assertions.assertNull(release.getSWID("UNKNOWN"));
    }
}
