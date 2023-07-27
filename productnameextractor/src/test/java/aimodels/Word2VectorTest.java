package aimodels;

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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Word2Vector class
 *
 * @author Richard Sawh
 */
public class Word2VectorTest {
    private static Word2Vector word2Vector;

    @BeforeAll
    public static void setUp() throws FileNotFoundException {
        // Initialize the Word2Vector instance with the model file path
        String modelPath = "nvip_data/data/w2v_model_250.bin";
        word2Vector = new Word2Vector(modelPath);
    }

    @Test
    public void testGetOutVectorLength() {
        // Verify that the expected vector length is greater than 0
        int vectorLength = word2Vector.getOutVectorLength();
        assertTrue(vectorLength > 0);
    }

    @Test
    public void testWord2Vector() {
        // Test word2vector method with a known word
        String word = "example";
        double[] vector = word2Vector.word2vector(word);

        // Verify that the returned vector is not null
        assertNotNull(vector);

        // Verify that the length of the returned vector matches the expected vector length
        int expectedVectorLength = word2Vector.getOutVectorLength();
        assertEquals(expectedVectorLength, vector.length);
    }

    @Test
    public void testWord2VectorWithUnknownWord() {
        // Test word2vector method with an unknown word
        String word = "eiwnfubeg";
        double[] vector = word2Vector.word2vector(word);

        // Verify that the returned vector is null for unknown words
        assertNull(vector);
//        assertArrayEquals(new double[0], vector);

    }

    @Test
    public void testWord2VectorWithEmptyWord() {
        // Test word2vector method with an empty word
        String word = "";
        double[] vector = word2Vector.word2vector(word);

        // Verify that the returned vector is null for empty words
        assertNull(vector);
    }
}
