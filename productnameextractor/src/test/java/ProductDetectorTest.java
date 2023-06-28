import edu.rit.se.nvip.CpeLookUp;
import edu.rit.se.nvip.NERmodel;
import edu.rit.se.nvip.ProductDetector;
import edu.rit.se.nvip.ProductNameExtractorController;
import edu.rit.se.nvip.model.cpe.ClassifiedWord;
import edu.rit.se.nvip.model.cpe.CpeGroup;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Class to test ProductDetectorTest
 *
 * @author Dylan Mulligan
 *
 */
public class ProductDetectorTest {
    private ProductDetector productDetector;
    private final String dataDir = System.getenv("DATA_DIR");

    @Before
    public void setUp() throws IOException {
        // Initialize ProductDetector with a mock CpeLookUp object or a real implementation for testing
        CpeLookUp cpeLookUp = new CpeLookUp();
        final Map<String, CpeGroup> productDict = ProductNameExtractorController.readProductDict("src/test/resources/data/test_product_dict.json");
        cpeLookUp.loadProductDict(productDict);
        productDetector = new ProductDetector(cpeLookUp, dataDir);

    }
    @Test
    public void classifyWordsInDescriptionTest() {
        String[] words = {"The", "software", "version", "is", "vulnerable", "before", "2.1.0"};
        float[] confidences = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.9f, 0.9f};
        NERmodel nerModel = mock(NERmodel.class);
        ArrayList<ClassifiedWord> nerResult = new ArrayList<>();
        ClassifiedWord word1 = new ClassifiedWord("The", confidences);
        ClassifiedWord word2 =new ClassifiedWord("software", confidences);
        ClassifiedWord word3 =new ClassifiedWord("version", confidences);
        ClassifiedWord word4 =new ClassifiedWord("is", confidences);
        ClassifiedWord word5 =new ClassifiedWord("vulnerable", confidences);
        ClassifiedWord word6 =new ClassifiedWord("before", confidences);
        ClassifiedWord word7 =new ClassifiedWord("2.1.0", confidences);

        nerResult.add(word1);
        nerResult.add(word2);
        nerResult.add(word3);
        nerResult.add(word4);
        nerResult.add(word5);
        nerResult.add(word6);
        nerResult.add(word7);
        when(nerModel.classifyComplex(words)).thenReturn(nerResult);

        String productResult = "[The: OTHER, software: OTHER, version: OTHER, is: OTHER, vulnerable: OTHER, before: SOFTWARE_VERSION, 2.1.0: SOFTWARE_VERSION]";

        assertTrue(productResult.contains( productDetector.classifyWordsInDescription(words).toString()));
        assertEquals(nerResult, nerModel.classifyComplex(words));

    }

    @Test
    public void testGetProductItemsWithDescriptionWords() {
        // Create a sample array of classified words
        ClassifiedWord word1 = new ClassifiedWord("Microsoft", new float[]{1.0f, 1.0f, 1.0f, 1.0f, 1.0f});
        ClassifiedWord word2 = new ClassifiedWord("Office", new float[]{1.0f, 1.0f, 1.0f, 1.0f, 1.0f});
        ClassifiedWord word3 = new ClassifiedWord("2.1.0", new float[]{1.0f, 1.0f, 1.0f, 1.0f, 1.0f});


        ArrayList<ClassifiedWord> classifiedWords = new ArrayList<>();
        classifiedWords.add(word1);
        classifiedWords.add(word2);
        classifiedWords.add(word3);


        String productItems = "[SN: Microsoft Office 2.1.0]";
        assertEquals(productItems, productDetector.getProductItems(classifiedWords).toString());


    }
}


