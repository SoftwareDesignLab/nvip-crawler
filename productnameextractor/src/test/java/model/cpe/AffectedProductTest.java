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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for AffectedProduct class
 *
 * @author Paul Vickers
 * @author Richard Sawh
 */
public class AffectedProductTest {

    @Test
    public void testEquals_WithEqualObjects() {
        // Create two AffectedProduct objects with different CVE ID and CPE
        AffectedProduct product1 = new AffectedProduct(1, "CVE-2023-1234", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");
        AffectedProduct product2 = new AffectedProduct(2, "CVE-2023-5678", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(product1, product2);
    }

    @Test
    public void testEquals_WithDifferentObjects() {
        // Create two AffectedProduct objects with different CPEs
        AffectedProduct Product1 = new AffectedProduct(1, "CVE-2023-1234", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");
        AffectedProduct Product2 = new AffectedProduct(2, "CVE-2023-5678", "cpe:2.3:a:vulnerable_product:2.0", "2023-01-01", "2.0");

        // Assert that the two objects are not equal
        Assertions.assertNotEquals(Product1, Product2);
    }

    @Test
    public void testEquals_WithNullObject() {
        // Create an AffectedProduct object
        AffectedProduct product = new AffectedProduct(1, "CVE-2023-1234", "cpe:2.3:a:vulnerable_product:1.0", "2023-01-01", "1.0");

        // Assert that the object is not equal to null
        Assertions.assertNotEquals(product, null);
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

        AffectedProduct product = new AffectedProduct(1, "", "", productName, "", version, vendor);

        assertEquals(expectedSWID, product.getSWID());
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

        AffectedProduct product = new AffectedProduct(1, "", "", productName, "", version, vendor);

        assertEquals(expectedSWID, product.getSWID());
    }

    //cveId, cpe, releaseDate are all empty string because they are not used for PURL Generation
    @org.junit.Test
    public void purlGenerationWOVersionTest(){
        String productName = "android";
        AffectedProduct product = new AffectedProduct(1, "", "", productName, "", "", "google");

        String expected = "pkg:google/android";

        assertEquals(expected,product.getPURL());
    }

    @org.junit.Test
    public void purlGenerationVersionTest(){
        String productName = "security";
        AffectedProduct product = new AffectedProduct(1, "", "", productName, "", "1.6.2", "gentoo");

        String expected = "pkg:gentoo/security@1.6.2";

        assertEquals(expected,product.getPURL());
    }
    
}
