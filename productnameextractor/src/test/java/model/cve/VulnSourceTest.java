package model.cve;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class VulnSourceTest {

    @Test
    public void testEquals_WithEqualObjects() {
        // Create two VulnSource objects with the same URL
        VulnSource source1 = new VulnSource("CVE-2023-1234", "https://example.com/source");
        VulnSource source2 = new VulnSource("CVE-2023-5678", "https://example.com/source");

        // Assert that the two objects are equal
        Assertions.assertEquals(source1, source2);
    }

    @Test
    public void testEquals_WithDifferentObjects() {
        // Create two VulnSource objects with different URLs
        VulnSource source1 = new VulnSource("CVE-2023-1234", "https://example.com/source1");
        VulnSource source2 = new VulnSource("CVE-2023-5678", "https://example.com/source2");

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(source1, source2);
    }

    @Test
    public void testEquals_WithNullObject() {
        // Create a VulnSource object
        VulnSource source = new VulnSource("CVE-2023-1234", "https://example.com/source");

        // Assert that the object is not equal to null
        Assertions.assertNotEquals(source, null);
    }

    @Test
    public void testHashCode_WithNullURL() {
        // Create a VulnSource object with a null URL
        VulnSource source = new VulnSource("CVE-2023-1234", null);

        // Assert that the hash code is 0
        Assertions.assertEquals(0, source.hashCode());
    }

    @Test
    public void testHashCode_WithNonNullURL() {
        // Create a VulnSource object with a non-null URL
        VulnSource source = new VulnSource("CVE-2023-1234", "https://example.com/source");

        // Assert that the hash code is as expected
        Assertions.assertEquals("https://example.com/source".hashCode(), source.hashCode());
    }
}