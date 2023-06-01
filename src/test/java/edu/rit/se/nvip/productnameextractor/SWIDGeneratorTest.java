package edu.rit.se.nvip.productnameextractor;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class SWIDGeneratorTest {

    @Test
    public void testGenerateSWID() {
        SWIDgenerator swidGenerator = new SWIDgenerator();

        // Create a sample ProductItem
        ProductItem productItem = new ProductItem("Product A");

        // Add some versions
        List<String> versions = Arrays.asList("1.0", "2.0");
        //break the versions before adding them
        for (String version : versions) {
            productItem.addVersion(version);
        }

        // Generate the SWID
        String swid = swidGenerator.generateSWID(productItem);

        // Check the SWID
        assertEquals("swid:Product_A:1.0:2.0", swid);

    }
}