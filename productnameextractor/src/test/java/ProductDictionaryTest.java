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

import edu.rit.se.nvip.ProductDictionary;
import edu.rit.se.nvip.model.cpe.CpeEntry;
import edu.rit.se.nvip.model.cpe.CpeGroup;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import static org.junit.jupiter.api.Assertions.*;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Product Dictionary Class Tests
 *
 * @author Paul Vickers
 * @author Richard Sawh
 * @author Dylan Mulligan
 *
 */

public class ProductDictionaryTest {
    @Test
    public void readProductDictSmallTest(){
        String productDictPath = "src/test/resources/data/test_product_dict_small.json";
        Map<String, CpeGroup> productDict = null;
        try{
            productDict = ProductDictionary.readProductDict(productDictPath);
        }catch(IOException e){

        }

        //Ensure product dict is expected size and is not null
        int expectedDictSize = 8;
        assertNotNull(productDict);
        assertEquals(productDict.size(), expectedDictSize);

        //Ensure specific properties of an entry are present and correct
        int expectedVersionsSize = 30;
        String expectedVendor = "libtiff";
        String expectedProduct = "libtiff";
        String specificVersion = "3.7.0";
        String expectedCpeID = "9D04B42B-8EA5-4516-A44A-083754D057E6";
        CpeGroup group = productDict.get("libtiff:libtiff");

        assertEquals(group.getVersions().size(), expectedVersionsSize);
        assertEquals(group.getVendor(), expectedVendor);
        assertEquals(group.getProduct(), expectedProduct);
        assertEquals(group.getVersions().get(specificVersion).getCpeID(), expectedCpeID);
    }

    @Test
    public void readProductDictLargeTest(){
        String productDictPath = "src/test/resources/data/test_product_dict_large.json";
        Map<String, CpeGroup> productDict = null;
        try{
            productDict = ProductDictionary.readProductDict(productDictPath);
        }catch(IOException e){

        }

        //Ensure product dict is expected size and is not null
        int expectedDictSize = 36;
        assertNotNull(productDict);
        assertEquals(productDict.size(), expectedDictSize);

        //Ensure specific properties of an entry are present and correct
        int expectedVersionsSize = 17;
        String expectedVendor = "walrus_digit";
        String expectedProduct = "walrack";
        String specificVersion = "2.0.1";
        String expectedCpeID = "B8AF1C7E-1962-49A3-9A83-53EAB916661D";
        CpeGroup group = productDict.get("walrus_digit:walrack");

        assertEquals(group.getVersions().size(), expectedVersionsSize);
        assertEquals(group.getVendor(), expectedVendor);
        assertEquals(group.getProduct(), expectedProduct);
        assertEquals(group.getVersions().get(specificVersion).getCpeID(), expectedCpeID);

    }

    @Test
    public void testWriteProductDict() throws IOException {
        //test file path
        String TEST_FILE_PATH = "src/test/resources/data/test_product_dict_creation.json";
        // Clean up the test file
        Path path = Paths.get(TEST_FILE_PATH);
        //clear file of changed data
        Files.write(path, "".getBytes());
        // Create sample product dictionary
        Map<String, CpeGroup> productDict = createSampleProductDict();

        // Write product dictionary to file
        ProductDictionary.writeProductDict(productDict, TEST_FILE_PATH);
        //write the contents of the file to the console
        FileReader reader = new FileReader(TEST_FILE_PATH);
        System.out.println("Contents of file: " + reader.read());
        // Read the written data from the file
        Map<String, CpeGroup> readProductDict = readProductDictFromFile(TEST_FILE_PATH);

        // Assertions to verify the data integrity
        assertEquals(productDict.size(), readProductDict.size(), "Number of products should match");

        for (Map.Entry<String, CpeGroup> entry : productDict.entrySet()) {
            String key = entry.getKey();
            CpeGroup expectedGroup = entry.getValue();
            CpeGroup actualGroup = readProductDict.get(key);

            Assertions.assertNotNull(actualGroup, "CpeGroup should not be null");
            Assertions.assertEquals(expectedGroup, actualGroup, "CpeGroup should match");
        }

    }

    private Map<String, CpeGroup> createSampleProductDict() {
        Map<String, CpeGroup> productDict = new LinkedHashMap<>();

        // Create sample CpeGroups
        CpeGroup group1 = new CpeGroup("Vendor1", "Product1", "CommonTitle1", new HashMap<>());
        CpeGroup group2 = new CpeGroup("Vendor2", "Product2", "CommonTitle2", new HashMap<>());
        CpeGroup group3 = new CpeGroup("Vendor3", "Product3", "CommonTitle3", new HashMap<>());

        // Add sample versions to the CpeGroups
        group1.getVersions().put("1.0", new CpeEntry("Title1", "1.0", "Update1", "CpeID1", "Platform1"));
        group2.getVersions().put("2.0", new CpeEntry("Title2", "2.0", "Update2", "CpeID2", "Platform2"));
        group2.getVersions().put("2.1", new CpeEntry("Title2", "2.1", "Update2", "CpeID2", "Platform2"));
        group3.getVersions().put("3.0", new CpeEntry("Title3", "3.0", "Update3", "CpeID3", "Platform3"));

        // Add the CpeGroups to the product dictionary
        productDict.put("Key1", group1);
        productDict.put("Key2", group2);
        productDict.put("Key3", group3);

        return productDict;
    }

    private Map<String, CpeGroup> readProductDictFromFile(String filePath) throws IOException {
        return ProductDictionary.readProductDict(filePath);
    }
}
