package productdetection;

import aimodels.NERmodel;
import model.cpe.ClassifiedWord;
import model.cpe.CpeGroup;
import env.ProductNameExtractorEnvVars;
import org.junit.Before;
import org.junit.Test;
import dictionary.ProductDictionary;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Class to test productdetection.ProductDetectorTest
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */
public class ProductDetectorTest {
    static{
        ProductNameExtractorEnvVars.initializeEnvVars();
    }
    private ProductDetector productDetector;
    private static final String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
    private static final String nlpDir = ProductNameExtractorEnvVars.getNlpDir();
    private static final String dataDir = ProductNameExtractorEnvVars.getDataDir();

    @Before
    public void setUp() throws IOException {
        // Initialize productdetection.ProductDetector with a mock productdetection.CpeLookUp object or a real implementation for testing
        CpeLookUp cpeLookUp = new CpeLookUp();
        final Map<String, CpeGroup> productDict = ProductDictionary.readProductDict("src/test/resources/data/test_product_dict.json");
        cpeLookUp.loadProductDict(productDict);
        productDetector = new ProductDetector(cpeLookUp, resourceDir, nlpDir, dataDir);

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

        assertTrue(productResult.contains(productDetector.classifyWordsInDescription(words).toString()));
        assertEquals(nerResult, nerModel.classifyComplex(words));

    }

    @Test
    public void getProductItemsWithDescriptionWordsTest() {
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


