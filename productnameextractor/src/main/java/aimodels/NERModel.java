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

import env.ProductNameExtractorEnvVars;
import model.cpe.ClassifiedWord;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.tokenize.WhitespaceTokenizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.api.preprocessor.DataNormalization;
import org.nd4j.linalg.dataset.api.preprocessor.serializer.NormalizerSerializer;
import org.nd4j.linalg.factory.Nd4j;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * NER class for classification words in the CVE description into "Software Name", "Software Version", and "Others"
 * 
 * Implementation of the Dong, Ying, Wenbo Guo, Yueqi Chen, Xinyu Xing, Yuqing Zhang, and Gang Wang. &quot;Towards the 
 * detection of inconsistencies in public security vulnerability reports.&quot; In 28th {USENIX} Security
 * Symposium ({USENIX} Security 19), pp. 869-885. 2019.
 * 
 * @author Igor Khokhlov
 * @author Dylan Mulligan
 * @author Paul Vickers
 *
 */

public class NERModel {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private final boolean timingOn = false;
	private MultiLayerNetwork model = null; // NER model
	private Char2Vector c2vModel; // Char2Vector model
	private Word2Vector w2vModel; // Word2Vector model
	static public final int numLabelClasses = 3; // Number of classes (SN, SV, O)
	private final int featureLength; // length of the input features vector.
	private final int wordVecLength; // Expected length of the word2vector model output. Later will be updated from the actual model
	private final int charVecLength; // Expected length of the char2vector model output. Later will be updated from the actual model
	private static Random rand = new Random(); // Needed in the case when word2vector model doesn't know the word

	public static final String SN = "SN", SV = "SV", OTHER = "O"; // class names
	private SentenceDetector sentenceDetector = null;
	private DataNormalization restoredNormalizer = null; // Feature normalizer

	/**
	 * Class constructor
	 */
	public NERModel(String modelsDir, String nlpDir) throws FileNotFoundException {
		super();

		try {
			String c2vModelConfigPath = modelsDir + ProductNameExtractorEnvVars.getChar2VecConfig();
			String c2vModelWeightsPath = modelsDir + ProductNameExtractorEnvVars.getChar2VecWeights();
			String w2vModelPath = modelsDir + ProductNameExtractorEnvVars.getWord2Vec();
			String nerModelPath = modelsDir + ProductNameExtractorEnvVars.getNerModel();
			String nerNormalizerPath = modelsDir + ProductNameExtractorEnvVars.getNerModelNormalizer();
			String sentenceModelPath = modelsDir + nlpDir + "/" + ProductNameExtractorEnvVars.getSentenceModel();

			long startTime = System.currentTimeMillis();
			// Load NER model
			try {
				model = MultiLayerNetwork.load(new File(nerModelPath), false);
			} catch (Exception e) {
				logger.error("Error loading MultiLayerNetwork for product name extraction from path {}: {}", nerModelPath, e.toString());
				logger.warn("Please ensure that your working directory is correct. Current working directory: {}", System.getProperty("user.dir"));
			}
			long endTime = System.currentTimeMillis();

			if (timingOn) {
				logger.info("Timing for NER model loading: " + (endTime - startTime) + "ms.");
			}

			// Load Char2Vector model
			startTime = System.currentTimeMillis();
			c2vModel = new Char2Vector(c2vModelConfigPath, c2vModelWeightsPath);
			endTime = System.currentTimeMillis();
			charVecLength = c2vModel.getOutVectorLength();

			if (timingOn) {
				logger.info("Timing for Char2Vector model initializing: " + (endTime - startTime) + "ms.");
			}

			// Load Word2Vector model
			startTime = System.currentTimeMillis();
			w2vModel = new Word2Vector(w2vModelPath);
			endTime = System.currentTimeMillis();
			wordVecLength = w2vModel.getOutVectorLength();

			if (timingOn) {
				logger.info("Timing for Word2Vector model initializing: " + (endTime - startTime) + "ms.");
			}

			rand = new Random();
			featureLength = wordVecLength + charVecLength;

			// Load Apache Open NLP sentence detector model
			if(!Files.exists(Paths.get(sentenceModelPath)))
				logger.info("Failed to find specified NER Model path '{}'", sentenceModelPath);

			try {
				startTime = System.currentTimeMillis();
				File binFile = new File(sentenceModelPath);
				InputStream modelIn = Files.newInputStream(binFile.toPath());
				SentenceModel sentenceModel = new SentenceModel(modelIn);
				sentenceDetector = new SentenceDetectorME(sentenceModel);
				modelIn.close();
				endTime = System.currentTimeMillis();
				if (timingOn) {
					logger.info("Timing for Sentence detector model loading: " + (endTime - startTime) + "ms.");
				}
			} catch (Exception e) {
				logger.error("Error loading sentence model for product name extraction from {}:\n{}", sentenceModelPath, e);
			}

			// Load features Normalizer
			startTime = System.currentTimeMillis();
			NormalizerSerializer loader = NormalizerSerializer.getDefault();
			try {
				restoredNormalizer = loader.restore(new File(nerNormalizerPath));
			} catch (Exception e) {
				logger.error("Error while restoring normalizer from {}: {}", nerNormalizerPath, e.toString());
			}
			endTime = System.currentTimeMillis();
			if (timingOn) {
				logger.info("Timing for Normalizer model loading: " + Long.toString(endTime - startTime) + "ms.");
			}
		} catch (Exception e) {
			logger.error("ERROR: Error initializing NERModel {}", e.toString());
			logger.warn("Please ensure that your working directory is correct. Current working directory: {}", System.getProperty("user.dir"));
			throw e;
		}

	}

	/**
	 * Classifies each word in the array of words (strings) as one of three classes (SN, SV, O)
	 * 
	 * @param words array of words to be classified
	 * @return Array of labels (strings) of classes
	 */
	public String[] classify(String[] words) {

		String[] result = new String[words.length];
		float[][] features = new float[words.length][featureLength];

		long startTime = System.currentTimeMillis();
		// Convert each word into a feature vector
		for (int i = 0; i < words.length; i++) {
			features[i] = word2vector(words[i], w2vModel, wordVecLength, c2vModel, charVecLength, logger);
		}

		long endTime = System.currentTimeMillis();
		if (timingOn) {
			logger.info("Timing for converting " + words.length + " words into 300 long feature vectors: " + (endTime - startTime) + "ms.");
		}

		INDArray featuresDL4J = Nd4j.zeros(1, featureLength, words.length);

		// Convert features into 3D-array acceptable by DL4J model
		int[] indices = new int[3];
		for (int i = 0; i < words.length; i++) {
			indices[2] = i;
			for (int j = 0; j < featureLength; j++) {
				indices[1] = j;
				featuresDL4J.putScalar(indices, features[i][j]);
			}
		}

		// Normalize features
		restoredNormalizer.transform(featuresDL4J);

		// Perform classification
		startTime = System.currentTimeMillis();
		INDArray out = model.output(featuresDL4J);
		endTime = System.currentTimeMillis();
		if (timingOn) {
			logger.info("Timing for description classification (model.output(featuresDL4J)): " + (endTime - startTime) + "ms.");
		}

		// Determine class based on the confidence levels of the model output
		float maxValue;
		float curValue;
		int classNum;

		for (int i = 0; i < words.length; i++) {
			indices[2] = i;
			maxValue = 0;
			classNum = 0;
			for (int j = 0; j < numLabelClasses; j++) {
				indices[1] = j;
				curValue = out.getFloat(indices);
				if (curValue > maxValue) {
					maxValue = curValue;
					classNum = j;
				}
			}
			// assign class labels
			result[i] = assignClassLabel(classNum);
		}

		return result;
	}

	/**
	 * Classifies each word in the array of words (strings) as one of three classes (SN, SV, O)
	 * 
	 * @param words array of words to be classified
	 * @return ArrayList of Classified Words (ClassifiedWord objects)
	 */
	public ArrayList<ClassifiedWord> classifyComplex(String[] words) {

		ArrayList<ClassifiedWord> result = new ArrayList<>();
		float[][] features = new float[words.length][featureLength];

		// Convert each word into a feature vector
		for (int i = 0; i < words.length; i++) {
			features[i] = word2vector(words[i], w2vModel, wordVecLength, c2vModel, charVecLength, logger);
		}

		INDArray featuresDL4J = Nd4j.zeros(1, featureLength, words.length);

		// Convert features into 3D-array acceptable by DL4J model
		int[] indices = new int[3];
		for (int i = 0; i < words.length; i++) {
			indices[2] = i;
			for (int j = 0; j < featureLength; j++) {
				indices[1] = j;
				featuresDL4J.putScalar(indices, features[i][j]);
			}
		}

		// Normalize features
		restoredNormalizer.transform(featuresDL4J);

		// Perform classification
		INDArray out = model.output(featuresDL4J);

		// Get confidence levels of the model output and create ClassifiedWord objects
		for (int i = 0; i < words.length; i++) {
			indices[2] = i;
			float[] confidences = new float[numLabelClasses];
			for (int j = 0; j < numLabelClasses; j++) {
				indices[1] = j;
				confidences[j] = out.getFloat(indices);
			}
			result.add(new ClassifiedWord(words[i], confidences));
		}

		return result;
	}

	/**
	 * Convert classes numbers into labels (SN, SV, O)
	 * 
	 * @param classNum class number
	 * @return String class label
	 */
	private String assignClassLabel(int classNum) {
		String classLabel;

		if (classNum == 0) {
			classLabel = SN;
		} else if (classNum == 1) {
			classLabel = SV;
		} else {
			classLabel = OTHER;
		}

		return classLabel;
	}

	/**
	 * Convert word into the 1D features vector
	 * 
	 * @param wordModel      word to be converted
	 * @param charModel model instance
	 * @param log         length of the Word2Vector vector
	 * @param charVecSize    model instance
	 * @param wordVecSize         length of the Char2Vector vector
	 * 
	 * @return features vector (length = length of the Word2Vector + length of the Char2Vector vector)
	 */
	public static float[] word2vector(String word, Word2Vector wordModel, int wordVecSize, Char2Vector charModel, int charVecSize, Logger log) {

		float[] wordVector = new float[wordVecSize + charVecSize];

		// get word embedding from Word2Vector model
		double[] wordVector1 = wordModel.word2vector(word);
		float[] wordVector2 = null;

		// get word embedding from Char2Vector model (on the character level)
		try {
			wordVector2 = charModel.word2vec(word);
		}catch (IllegalArgumentException e){
			//This gets thrown whenever russian or chinese characters are passed in; errors clog up logs
		}catch (Exception e) {
			log.error(e + " for word " + word);
		}

		// convert double[] to float[]
		if (wordVector2 == null) {
			wordVector2 = new float[charVecSize];
		}

		for (int i = 0; i < wordVecSize; i++) {
			if (wordVector1 != null) {
				wordVector[i] = (float) wordVector1[i];
			}
			// if word2vector model does not know the word, generate vector random values
			else {
				wordVector[i] = rand.nextFloat() * 2 - 1; // has to be between -1 and 1
			}
		}

		// Concatenate vectors
		if (wordVecSize + charVecSize - wordVecSize >= 0)
			System.arraycopy(wordVector2, 0, wordVector, wordVecSize, wordVecSize + charVecSize - wordVecSize);

		return wordVector;
	}

	/**
	 * classify words in the description into one of three classes (SN, SV, O)
	 * 
	 * @param description description text
	 * 
	 * @return ArrayList of strings arrays. Each array contains word (index=0) and the assigned class
	 *         (index=1)
	 */
	public ArrayList<String[]> classify(String description) {
		ArrayList<String[]> result = new ArrayList<>();

		// Split description into sentences
		String[] sentences = sentenceDetector.sentDetect(description);

		// Split description into words
		ArrayList<String> wordsList = new ArrayList<>();
		for (String sent : sentences) {
			String[] whitespaceTokenizerLine = WhitespaceTokenizer.INSTANCE.tokenize(sent);
			wordsList.addAll(Arrays.asList(whitespaceTokenizerLine));
		}

		// convert ArrayList into array of strings
		String[] words = wordsList.toArray(new String[0]);

		// Perform classification
		String[] resultClasses = classify(words);

		// assemble the output
		for (int i = 0; i < words.length; i++) {
			result.add(new String[] { words[i], resultClasses[i] });
		}

		return result;
	}

}
