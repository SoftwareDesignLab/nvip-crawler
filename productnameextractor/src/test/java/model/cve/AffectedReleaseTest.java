package model.cve;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

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

    @org.junit.Test
    public void swidGenerationVersionTest(){
        String expectedSWID = "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\" " +
                "name=\"Example Software\" " +
                "tagId=\"ExampleVendor.ExampleSoftware.1.0.0\" " +
                "version=\"1.0.0\">" +
                "<Entity name=\"ExampleVendor\" regid=\"com.ExampleVendor\">" +
                "<Meta product=\"Example Software\" colloquialVersion=\"1.0.0\"/>" +
                "<Payload>" +
                "<File name=\"ExampleSoftware.exe\" size=\"532712\" SHA256:hash=\"a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a\"/>" +
                "</Payload>" +
                "</SoftwareIdentity>";

        String productName = "Example Software";
        String vendor = "ExampleVendor";
        String version = "1.0.0";

        AffectedRelease product = new AffectedRelease(1, "", "", "", version, vendor);

        assertEquals(expectedSWID, product.getSWID(productName));
    }

    @org.junit.Test
    public void swidGenerationWOVersionTest() {
        String expectedSWID = "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\" " +
                "name=\"Example Software\" " +
                "tagId=\"ExampleVendor.ExampleSoftware\" " +
                "version=\"\">" +
                "<Entity name=\"ExampleVendor\" regid=\"com.ExampleVendor\">" +
                "<Meta product=\"Example Software\" colloquialVersion=\"\"/>" +
                "<Payload>" +
                "<File name=\"ExampleSoftware.exe\" size=\"532712\" SHA256:hash=\"a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a\"/>" +
                "</Payload>" +
                "</SoftwareIdentity>";

        String productName = "Example Software";
        String vendor = "ExampleVendor";
        String version = "";

        AffectedRelease product = new AffectedRelease(1, "", "", "", version, vendor);

        assertEquals(expectedSWID, product.getSWID(productName));
    }

    @org.junit.Test
    public void swidGenerationProductUNKNOWN(){

        String productName = "UNKNOWN";
        String vendor = "ExampleVendor";
        String version = "1.0.0";

        AffectedRelease product = new AffectedRelease(1, "", "", "", version, vendor);

        assertNull(product.getSWID(productName));
    }

    //cveId, cpe, releaseDate are all empty string because they are not used for PURL Generation
    @org.junit.Test
    public void purlGenerationWOVersionTest(){
        String productName = "android";
        AffectedRelease product = new AffectedRelease(1, "", "", "", "", "google");

        String expected = "pkg:google/android";

        assertEquals(expected,product.getPURL(productName));
    }

    @org.junit.Test
    public void purlGenerationVersionTest(){
        String productName = "security";
        AffectedRelease product = new AffectedRelease(1, "", "", "", "1.6.2", "gentoo");

        String expected = "pkg:gentoo/security@1.6.2";

        assertEquals(expected,product.getPURL(productName));
    }

    @org.junit.Test
    public void purlGenerationProductUNKNOWN(){
        String productName = "UNKNOWN";
        AffectedRelease product = new AffectedRelease(1, "", "", "", "1.6.2", "gentoo");

        assertNull(product.getPURL(productName));
    }
}
