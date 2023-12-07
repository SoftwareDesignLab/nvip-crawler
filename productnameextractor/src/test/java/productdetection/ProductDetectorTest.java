/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

package productdetection;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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

import aimodels.NERModel;
import edu.rit.se.nvip.db.model.CpeGroup;
import model.cpe.ClassifiedWord;
import env.ProductNameExtractorEnvVars;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import dictionary.ProductDictionary;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ProductDetector class
 *
 * @author Dylan Mulligan
 * @author Paul Vickers
 * @author Richard Sawh
 *
 */
@ExtendWith(MockitoExtension.class)
public class ProductDetectorTest {

    @Mock NERModel nerModel;

    static CpeLookUp cpeLookUp;

    private ProductDetector productDetector;
    private static final String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
    private static final String nlpDir = ProductNameExtractorEnvVars.getNlpDir();
    private static final String dataDir = ProductNameExtractorEnvVars.getDataDir();

    @BeforeAll
    static void setUpAllTests() throws IOException {
        ProductNameExtractorEnvVars.initializeEnvVars();

        // Initialize ProductDetector with a mock CpeLookUp object or a real implementation for testing
        cpeLookUp = new CpeLookUp();
        final Map<String, CpeGroup> productDict = ProductDictionary.readProductDict("src/test/resources/data/test_product_dict.json");
        cpeLookUp.loadProductDict(productDict);
    }

    @BeforeEach
    public void setUp() throws IOException {
        productDetector = new ProductDetector(cpeLookUp, resourceDir, nlpDir, dataDir);
    }

    @Test
    public void classifyWordsInDescriptionTest() {
        String[] words = {"The", "software", "version", "is", "vulnerable", "before", "2.1.0"};
        float[] confidences = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.9f, 0.9f};
        ArrayList<ClassifiedWord> nerResult = new ArrayList<>();
        ClassifiedWord word1 = new ClassifiedWord("The", confidences);
        ClassifiedWord word2 = new ClassifiedWord("software", confidences);
        ClassifiedWord word3 = new ClassifiedWord("version", confidences);
        ClassifiedWord word4 = new ClassifiedWord("is", confidences);
        ClassifiedWord word5 = new ClassifiedWord("vulnerable", confidences);
        ClassifiedWord word6 = new ClassifiedWord("before", confidences);
        ClassifiedWord word7 = new ClassifiedWord("2.1.0", confidences);

        nerResult.add(word1);
        nerResult.add(word2);
        nerResult.add(word3);
        nerResult.add(word4);
        nerResult.add(word5);
        nerResult.add(word6);
        nerResult.add(word7);
        when(nerModel.classifyComplex(ArgumentMatchers.eq(words))).thenReturn(nerResult);


        String productResult = "[The: OTHER, software: OTHER, version: OTHER, is: OTHER, vulnerable: OTHER, before: SOFTWARE_VERSION, 2.1.0: SOFTWARE_VERSION]";

        assertEquals(productResult, productDetector.classifyWordsInDescription(words).toString());
        assertEquals(nerResult.toString(), nerModel.classifyComplex(words).toString());
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


