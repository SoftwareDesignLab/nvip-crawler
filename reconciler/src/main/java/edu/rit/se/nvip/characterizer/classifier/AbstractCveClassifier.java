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
package edu.rit.se.nvip.characterizer.classifier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.InstanceComparator;
import weka.core.Instances;
import weka.core.converters.CSVLoader;
import weka.core.tokenizers.NGramTokenizer;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.AddValues;
import weka.filters.unsupervised.attribute.NominalToString;
import weka.filters.unsupervised.attribute.StringToWordVector;

import java.io.*;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * 
 * 
 * @author axoeec
 *
 */
public abstract class AbstractCveClassifier {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	protected NumberFormat formatter = new DecimalFormat("#0.000");
	protected String sCommaSeparatedCsvData = null;
	protected Instances myInstances;
	protected boolean testMultiClassPrediction = true;
	protected String cveClassifierName = "AbstractCveClassifier";
	protected String preProcessedTrainingDataFile = null;
	private AddValues addValueFilter = new AddValues();

	protected boolean useNGrams = true; // use NGrams while applying StringToWrodVector filter?

	/**
	 * train a ML model based on the underlying classification approach. Use the
	 * data provided
	 * 
	 * @param instances
	 * @throws Exception
	 */
	protected abstract void trainMLModel(Instances instances) throws Exception;

	protected abstract ArrayList<String[]> predict(Instance currentInstance, boolean bPredictMultiple);

	public abstract void resetClassifier(Object classifier);

	protected abstract Map<String, Integer> getModelData(String label);

	/**
	 * train a ML model based on the underlying classification approach. Use the
	 * data that you already have!
	 * 
	 * @return
	 */

	public void trainMLModel() {
		String info = "";
		try {
			trainMLModel(myInstances);
		} catch (Exception e) {
			info = "Oops, an error occured! Check your training data, Detail: " + e.toString();
			logger.error(info);
		}
	}

	/**
	 * Predict the label for <sCommaSeparatedAttribs>
	 * 
	 * @param sCommaSeparatedAttribs
	 * @param bPredictMultiple
	 * @return
	 */
	public ArrayList<String[]> predict(String sCommaSeparatedAttribs, boolean bPredictMultiple) {
		ArrayList<String[]> prediction = new ArrayList<String[]>();
		try {
			Instance currentInstance = createInstanceFromCommaSeparatedAttribs(sCommaSeparatedAttribs, true);

			prediction = predict(currentInstance, bPredictMultiple);
		} catch (Exception e) {
			logger.error("Error during predict() instance count:" + myInstances.numInstances(), e);
			e.printStackTrace();
		}
		return prediction;
	}

	/**
	 * get instances that have a label in <labels> hash for training. You must
	 * exclude current test instance <excludedTestInstance>
	 *
	 * @param labels
	 * @param myInstances
	 * @return
	 */
	protected Instances getSubsetOfInstances(HashMap<String, Integer> labels, Instances myInstances, Instance excludedTestInstance) {
		Instances instances = new Instances(myInstances, -1);
		InstanceComparator instanceComparator = new InstanceComparator();
		for (Instance instance : myInstances)
			if (labels.containsKey(instance.stringValue(instance.classAttribute())) && (instanceComparator.compare(instance, excludedTestInstance) != 0))
				instances.add(instance);
		return instances;
	}

	/**
	 * create a weka instance from comma separated string
	 *
	 * @param sCommaSeparatedAttribRows
	 * @param useNGrams                 TODO
	 * @return
	 */
	protected Instances getInstacesFromCsvString(String sCommaSeparatedAttribRows, boolean useNGrams) {

		try {
			InputStream stream = new ByteArrayInputStream(sCommaSeparatedAttribRows.getBytes());

			// load CSV structure
			CSVLoader loader = new CSVLoader();
			loader.setSource(stream);
			// the first column is the description and the second one is the label!!
			loader.setStringAttributes("1");
			loader.setNominalAttributes("2");
			myInstances = loader.getDataSet();

			myInstances.setClassIndex(myInstances.numAttributes() - 1); // here the index starts from 0!

			// Nominal to String
			myInstances = nominalToStringFilter(myInstances);

			// String To Word Vector
			myInstances = stringToWordVectorFilter(myInstances, useNGrams);

			// log data for trace/debug
			dumpData(preProcessedTrainingDataFile + ".arff");
		} catch (IOException e) {
			logger.error(e.toString());
		}

		return myInstances;
	}

	/**
	 * Nominal To String Filter
	 *
	 * @param myInstances
	 * @return
	 */
	private Instances nominalToStringFilter(Instances myInstances) {
		try {
			NominalToString nomToStringFilter = new NominalToString();
			nomToStringFilter.setAttributeIndexes("first"); // assuming the description if the first column
			nomToStringFilter.setInputFormat(myInstances);
			myInstances = Filter.useFilter(myInstances, nomToStringFilter);
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return myInstances;

	}

	/**
	 * string To Word Vector Filter
	 *
	 * @param myInstances
	 * @param useNGrams   TODO
	 * @return
	 */
	private Instances stringToWordVectorFilter(Instances myInstances, boolean useNGrams) {
		try {
			int attribCount = myInstances.numAttributes();
			StringToWordVector stringToWordFilter = new StringToWordVector();

			/**
			 * When we use entropy, we already calculate probability, so do not need term
			 * frequency(tf). Because we distribute entropy, we do not want to use inverse
			 * document frequency(idf) either!
			 */
			if (!(this instanceof EntropyBasedCveClassifier)) {
				stringToWordFilter.setTFTransform(true);
				stringToWordFilter.setIDFTransform(true);
				stringToWordFilter.setOutputWordCounts(true);
			}
			if (useNGrams) {
				NGramTokenizer tokenizer = new NGramTokenizer();
				tokenizer.setNGramMinSize(1);
				tokenizer.setNGramMaxSize(3);
				tokenizer.setDelimiters(" ");
				stringToWordFilter.setTokenizer(tokenizer); // set tokenizer!
			}
			stringToWordFilter.setInputFormat(myInstances);
			myInstances = Filter.useFilter(myInstances, stringToWordFilter);

			logger.info("StringToWordVector filter applied: " + "# of attributes changed from " + attribCount + " to " + myInstances.numAttributes() + " UsedNGrams: " + useNGrams);
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return myInstances;
	}

	/**
	 * Create an Instance from a comma separated string
	 *
	 * @param sCommaSeparatedAttribs Comma separated string that stores attribs
	 * @param classIsmissing         sCommaSeparatedAttribs does not include the
	 *                               class attrib
	 * @return Created instance
	 */
	protected Instance createInstanceFromCommaSeparatedAttribs(String sCommaSeparatedAttribs, boolean classIsmissing) {

		DenseInstance currentInstance;
		try {

			String[] attribs = sCommaSeparatedAttribs.split(",");
			int numberOfAttribs = myInstances.numAttributes();
			double[] instanceValues = new double[numberOfAttribs];

			// set numeric attribs: store nominal attrib indexes
			ArrayList<Integer> nominalIndexList = new ArrayList<>();

			for (int i = 1; i < numberOfAttribs - 1; i++) {

				try {
					String sToken = myInstances.attribute(i).name();
					if (sCommaSeparatedAttribs.contains(sToken)) {
						// binary
						instanceValues[i] = 1;
					}
				} catch (Exception e) {
					logger.error("Could not parse " + attribs[i] + ", attrib is nominal?");
					instanceValues[i] = 0;
					nominalIndexList.add(i);
				}
			}

			currentInstance = new DenseInstance(1.0, instanceValues);
			currentInstance.setDataset(myInstances);

			/**
			 * assign non numeric values if the index of non-numeric attrib is 3, the 3th
			 * index of currentInstance becomes attrib[3]
			 */
			for (int i = 0; i < nominalIndexList.size(); i++) {
				int nominalAttributeIndex = nominalIndexList.get(i);
				currentInstance.setValue(nominalAttributeIndex, attribs[nominalAttributeIndex]);
			}
			if (classIsmissing) {
				currentInstance.setMissing(0); // set last value as ?
			} else {
				String value = attribs[attribs.length - 1]; // get last value from attribs array
				if (myInstances.classAttribute().indexOfValue(value + "") == -1) {
					// this new class does not exist among the current classes, so add it!!
					myInstances = addValueToClassAttrib(myInstances, value + "");
					currentInstance.setDataset(myInstances);
				}
				int index = myInstances.classAttribute().indexOfValue(value + "");
				currentInstance.setValue(currentInstance.numAttributes() - 1, index);
			}
		} catch (Exception e) {
			logger.error(e.toString());
			currentInstance = null;
		}
		return currentInstance;
	}

	/**
	 * Add a new class label
	 *
	 * @param instances
	 * @param value
	 * @return
	 */
	protected Instances addValueToClassAttrib(Instances instances, String value) {
		try {
			String classIndex = instances.numAttributes() + ""; // the index starts from 1
			addValueFilter.setAttributeIndex(classIndex);
			addValueFilter.setLabels(value);
			addValueFilter.setInputFormat(instances);

			instances = Filter.useFilter(instances, addValueFilter);
		} catch (Exception e) {
			logger.error(e.toString());
			e.printStackTrace();
		}
		return instances;
	}

	public String getCveClassifierName() {
		return cveClassifierName;
	}

	public void setCveClassifierName(String cveClassifierName) {
		this.cveClassifierName = cveClassifierName;
	}

	public void dumpData(String filePath) {
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
			writer.write(myInstances.toString());
			writer.flush();
			writer.close();
		} catch (IOException e) {
			logger.error(e.toString());
		}
	}
	public void setAddValueFilter(AddValues add){
		addValueFilter = add;

	}
}
