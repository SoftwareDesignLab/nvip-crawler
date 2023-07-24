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

import java.io.IOException;
import java.util.ArrayList;

import model.cpe.ClassifiedWord;
import model.cpe.ProductItem;
import env.ProductNameExtractorEnvVars;
import org.junit.Test;
import productdetection.ProductDetector;

import static org.junit.Assert.*;

/**
 * Unit tests for the NERmodel and DetectProduct classes
 *
 * @author Igor Khokhlov
 * @author Paul Vickers
 * @author Dylan Mulligan
 * @author Richard Sawh
 *
 */

public class NERmodelTest {

	// Statically load environment variables
	static{
		ProductNameExtractorEnvVars.initializeEnvVars();
	}
	private static final String RESOURCE_DIR = ProductNameExtractorEnvVars.getResourceDir();
	private static final String NLP_DIR = ProductNameExtractorEnvVars.getNlpDir();
	private static final String DATA_DIR = ProductNameExtractorEnvVars.getDataDir();
	private static final String CHAR_2_VEC_CONFIG = ProductNameExtractorEnvVars.getChar2VecConfig();
	private static final String CHAR_2_VEC_WEIGHTS = ProductNameExtractorEnvVars.getChar2VecWeights();
	private static final String WORD_2_VEC = ProductNameExtractorEnvVars.getWord2Vec();

	@Test
	public void char2vectorModelTest() {

		String word = "MicroSoft";

		String modelsDir = RESOURCE_DIR + "/" + DATA_DIR + "/";
		String c2vModelConfigPath = modelsDir + CHAR_2_VEC_CONFIG;
		String c2vModelWeightsPath = modelsDir + CHAR_2_VEC_WEIGHTS;

		Char2vec c2vModel = new Char2vec(c2vModelConfigPath, c2vModelWeightsPath);
		int charVecLength = c2vModel.getOutVectorLength();

		long startTime = System.currentTimeMillis();

		float[] charVector = c2vModel.word2vec(word);

		long endTime = System.currentTimeMillis();
		System.out.println("Timing for embedding word '" + word +"' on the character level: " + Long.toString(endTime-startTime) + "ms.");

		boolean correctLength = false;
		boolean notNull = (charVector != null);

			if (notNull) {
				correctLength = (charVector.length == charVecLength);
			}

		assertTrue((correctLength && notNull));

	}

	@Test
	public void word2vectorModelTest() {
		String word = "MicroSoft";
		String w2vModelPath = RESOURCE_DIR + "/" + DATA_DIR + "/" + WORD_2_VEC;
		Word2Vector w2vModel = null;
		try {
			w2vModel = new Word2Vector(w2vModelPath);
		} catch (Exception e) {
			fail(e.toString());
		}
		int wordVecLength = w2vModel.getOutVectorLength();

		long startTime = System.currentTimeMillis();
		double[] wordVector = w2vModel.word2vector(word);
		long endTime = System.currentTimeMillis();
		System.out.println("Timing for embedding word '" + word +"' on the word level: " + Long.toString(endTime-startTime) + "ms.");

		assertNotNull("Test failed: wordVector was null", wordVector);

		boolean correctLength = (wordVector.length == wordVecLength);

		assertTrue("Test failed: correctLength was false", correctLength);
	}

	@Test
	public void nerModelTest() {

		String testDescription = "The daemon in rsync 3.1.2 and 3.1.3-development before 2017-12-03 does not check for fnamecmp filenames in the daemon_filter_list data structure (in the recv_files function in receiver.c) and also does not apply the sanitize_paths protection mechanism to pathnames found in \"xname follows\" strings (in the read_ndx_and_attrs function in rsync.c) which allows remote attackers to bypass intended access restrictions.";

		long startTime = System.currentTimeMillis();
		NERmodel nerModel = null;
		try {
			nerModel = new NERmodel(RESOURCE_DIR + "/" + DATA_DIR + "/", NLP_DIR);
		} catch (Exception e) {
			fail(e.toString());
		}
		long endTime = System.currentTimeMillis();
		System.out.println("Timing for overall NER model initialization: " + Long.toString(endTime-startTime) + "ms.");


		startTime = System.currentTimeMillis();
		ArrayList<String[]> result = nerModel.classify(testDescription);
		endTime = System.currentTimeMillis();
		System.out.println("Timing for the classification of description of the average length: " + Long.toString(endTime-startTime) + "ms.");

		boolean notNull = (result != null);
		boolean lengthNotZero = false;
		boolean hasOther = false;
		boolean hasSN = false;
		boolean hasSV = false;

		if (notNull) {
			lengthNotZero = result.size()>0;
			hasOther = result.get(0)[1].equals(NERmodel.OTHER);
			hasSN = result.get(3)[1].equals(NERmodel.SN);
			hasSV = result.get(4)[1].equals(NERmodel.SV);
		}

		assertTrue("Result is not empty ", (notNull && lengthNotZero));
		assertTrue("Result contains \"OTHER\" class", hasOther);
		assertTrue("Result contains \"SOFTWARE NAME\" class", hasSN);
		assertTrue("Result contains \"SOFTWARE VERSION\" class", hasSV);
	}

	@Test
	public void augmentedNERtest() {
		String description = "There is a DoS vulnerability in Pillow before 6.2.2 caused by FpxImagePlugin.py calling the range function on an unvalidated 32-bit integer if the number of bands is large. On Windows running 32-bit Python, this results in an OverflowError or MemoryError due to the 2 GB limit. However, on Linux running 64-bit Python this results in the process being terminated by the OOM killer.\n";
		String anticipatedResult = "SN: Pillow. SV:  before 6.2.2";

		ProductDetector nameDetector;
		try {
			nameDetector = new ProductDetector(null, RESOURCE_DIR, NLP_DIR, DATA_DIR);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		long startTime = System.currentTimeMillis();
		ArrayList<ClassifiedWord> result = nameDetector.classifyWordsInDescription(description);
		long endTime = System.currentTimeMillis();

		System.out.println("Timing for the classification of description of the average length using augmented NER: " + (endTime - startTime) + "ms.");

		ArrayList<ProductItem> detectedProducts = nameDetector.getProductItems(result);

		boolean isResultNotNull = (result != null && !result.isEmpty());
		boolean containsOtherClass = result.stream().anyMatch(word -> word.getAssignedClass() == ClassifiedWord.WordType.OTHER);
		boolean containsSoftwareNameClass = result.stream().anyMatch(word -> word.getAssignedClass() == ClassifiedWord.WordType.SOFTWARE_NAME);
		boolean containsSoftwareVersionClass = result.stream().anyMatch(word -> word.getAssignedClass() == ClassifiedWord.WordType.SOFTWARE_VERSION);

		boolean isProductNotNull = (detectedProducts != null && !detectedProducts.isEmpty());
		boolean isCorrectProduct = detectedProducts.get(0).toString().contains(anticipatedResult);

		if (!isCorrectProduct) {
			System.out.println("ERROR! Anticipated: " + anticipatedResult + " | Got: " + detectedProducts.get(0).toString());
		}
		System.out.println("Result: " + detectedProducts.get(0).toString());

		assertTrue("Result is not empty", isResultNotNull);
		assertTrue("Result contains \"OTHER\" class", containsOtherClass);
		assertTrue("Result contains \"SOFTWARE NAME\" class", containsSoftwareNameClass);
		assertTrue("Result contains \"SOFTWARE VERSION\" class", containsSoftwareVersionClass);
		assertTrue("Product is not empty", isProductNotNull);
		assertTrue("Result is correct", isCorrectProduct);
	}

}
