import model.cpe.CpeGroup;
import org.junit.Test;

import java.io.IOException;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Class to test ProductNameExtractorController
 *
 * @author Dylan Mulligan
 *
 */
public class ProductNameExtractorControllerTest {
    @Test
    public void fetchEnvVarsTest(){

    }

    @Test
    public void readProductDictMainTest(){
        String productDictPath = "src/main/resources/data/product_dict.json";
        Map<String, CpeGroup> productDict = null;
        try{
            productDict = ProductNameExtractorController.readProductDict(productDictPath);
        }catch(IOException e){

        }

        //Ensure product dict size is greater than 0 and not null
        assertNotNull(productDict);
        assertTrue(productDict.size() > 0);

        //Ensure specific properties of an entry are present and correct
        int expectedVersionsSize = 1;
        String expectedVendor = "canon";
        String expectedProduct = "imagerunner_5000i";
        String specificVersion = "-";
        String expectedCpeID = "88FD64E8-67E8-415D-A798-4DC26EA8E7B5";
        CpeGroup group = productDict.get("canon:imagerunner_5000i");

        assertEquals(group.getVersions().size(), expectedVersionsSize);
        assertEquals(group.getVendor(), expectedVendor);
        assertEquals(group.getProduct(), expectedProduct);
        assertEquals(group.getVersions().get(specificVersion).getCpeID(), expectedCpeID);

    }

    @Test
    public void readProductDictSmallTest(){
        String productDictPath = "src/test/resources/data/test_product_dict1.json";
        Map<String, CpeGroup> productDict = null;
        try{
            productDict = ProductNameExtractorController.readProductDict(productDictPath);
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
        String productDictPath = "src/test/resources/data/test_product_dict2.json";
        Map<String, CpeGroup> productDict = null;
        try{
            productDict = ProductNameExtractorController.readProductDict(productDictPath);
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
}
