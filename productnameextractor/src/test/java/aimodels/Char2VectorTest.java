package aimodels;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import env.ProductNameExtractorEnvVars;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Char2Vector class
 *
 * @author Richard Sawh
 */
public class Char2VectorTest {
    private Char2Vector char2Vector;

    static{
        ProductNameExtractorEnvVars.initializeEnvVars();
    }

    private static final String RESOURCE_DIR = ProductNameExtractorEnvVars.getResourceDir();
    private static final String DATA_DIR = ProductNameExtractorEnvVars.getDataDir();
    private static final String CHAR_2_VEC_CONFIG = ProductNameExtractorEnvVars.getChar2VecConfig();
    private static final String CHAR_2_VEC_WEIGHTS = ProductNameExtractorEnvVars.getChar2VecWeights();

    @BeforeEach
    public void setUp() {
        String modelConfigPath = RESOURCE_DIR + "/" + DATA_DIR + "/" + CHAR_2_VEC_CONFIG;
        String modelWeightsPath = RESOURCE_DIR + "/" + DATA_DIR + "/" + CHAR_2_VEC_WEIGHTS;
        char2Vector = new Char2Vector(modelConfigPath, modelWeightsPath);
    }

    @Test
    public void testGetOutVectorLength() {
        // Test the getOutVectorLength() method
        int expectedLength = 50;
        int actualLength = char2Vector.getOutVectorLength();
        assertEquals(expectedLength, actualLength);
    }

    @Test
    public void testWord2vecWithKnownWord() {
        // Test word2vec method with a known word
        String word = "hello";
        float[] vector = char2Vector.word2vec(word);

        // Verify that the returned vector is not null
        assertNotNull(vector);
        // Verify that the length of the vector matches the expected length
        int expectedLength = char2Vector.getOutVectorLength();
        assertEquals(expectedLength, vector.length);
    }

    @Test
    public void testWord2vecWithUnknownWord() {
        // Test word2vec method with an unknown word
        String word = "$#@!";
        float[] vector = char2Vector.word2vec(word);

        // Verify that the returned vector is an array of all zeros
        assertNotNull(vector);
        assertEquals(char2Vector.getOutVectorLength(), vector.length);
    }
}
