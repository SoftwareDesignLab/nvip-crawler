/**
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
*/

package aimodels;

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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.models.embeddings.loader.WordVectorSerializer;
import org.deeplearning4j.models.word2vec.Word2Vec;

import java.io.FileNotFoundException;

/**
 * Word2Vector class for words embedding into 1D-vector
 * 
 * @author Igor Khokhlov
 *
 */

public class Word2Vector {

	private final Word2Vec model;

	// This value is later updated from the loaded model
	private final int vectorLength;

	/**
	 * Class constructor
	 * @param modelPath String Model file path
	 */		
	public Word2Vector(String modelPath) throws RuntimeException, FileNotFoundException {
		super();
		
		try {
			//Try to load the model
			model = WordVectorSerializer.loadFullModel(modelPath);

			//get expected vector length
			vectorLength = model.vectorSize();
		} catch (Exception e) {
			Logger logger = LogManager.getLogger(getClass().getSimpleName());
			logger.warn("Could not find w2v model at path {}, if running locally please ensure that w2v_model_250.bin has been" +
					" stored in productnameextractor/nvip_data/data", modelPath);
			logger.warn("Please ensure that your working directory is correct. Current working directory: {}", System.getProperty("user.dir"));
			throw e;
		}		
	}
	
	/**
	 * Returns expected length of the vector after word embedding
	 * 
	 * @return expected length of the vector after word embedding
	 */	
	public int getOutVectorLength() {		
		return vectorLength;
	}
	
	/**
	 * Convert word into the 1D-vector
	 * 
	 * @param word input word
	 * @return array of double values
	 */	
	public double[] word2vector(String word) {
		double[] doubleArray = null;

		try { doubleArray = model.getWordVector(word.toLowerCase()); }
		catch (Exception ignored) { }
		
		return doubleArray;
	}

}
