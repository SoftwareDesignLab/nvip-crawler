import model.AffectedRelease;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SWIDTest {
    @Test
    public void swidGenerationVersionTest(){
        String expectedSWID = "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\" " +
                "name=\"Example Software\" " +
                "tagId=\"ExampleVendor.ExampleSoftware.1.0.0\" " +
                "version=\"1.0.0\">" +
                "<Entity name=\"ExampleVendor\" regid=\"ExampleVendor\" role=\"tagCreator softwareCreator\"/>" +
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

    @Test
    public void swidGenerationWOVersionTest() {
        String expectedSWID = "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\" " +
                "name=\"Example Software\" " +
                "tagId=\"ExampleVendor.ExampleSoftware\" " +
                "version=\"\">" +
                "<Entity name=\"ExampleVendor\" regid=\"ExampleVendor\" role=\"tagCreator softwareCreator\"/>" +
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

    @Test
    public void swidGenerationProductUNKNOWN(){

        String productName = "UNKNOWN";
        String vendor = "ExampleVendor";
        String version = "1.0.0";

        AffectedRelease product = new AffectedRelease(1, "", "", "", version, vendor);

        assertNull(product.getSWID(productName));
    }
}
