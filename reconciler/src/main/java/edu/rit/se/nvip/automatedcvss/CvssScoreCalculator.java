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
package edu.rit.se.nvip.automatedcvss;

import com.opencsv.CSVReader;
import edu.rit.se.nvip.model.CVSSVector;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.python.core.PyList;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 * @author axoeec
 *
 */
public class CvssScoreCalculator {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	String pythonPyFile = "evaluateCVSSpartialsv2.0.py"; // new version
	String pythonMethodName = "get_cvss_for_partial";
	PyObject pyFunction = null;
	PythonInterpreter myPythonInterpreter = new PythonInterpreter();
	Map<CVSSVector, Double> scoreTable;

	/**
	 * Initialize Python Interpreter and get a reference to the <pythonMethodName>
	 * method
	 */
	public CvssScoreCalculator(PythonInterpreter pythonInt) {
		myPythonInterpreter = pythonInt;
		logger.info("Initializing PythonInterpreter for " + pythonMethodName + " in " + pythonPyFile);

		// change the directory and execute the .py script
		String workingDir = ReconcilerEnvVars.getDataDir() + "/cvss/";
		logger.info("Importing os for jython...");
		myPythonInterpreter.exec("import os");
 		logger.info("Changing dir to {} for jython. Current directory is {}", workingDir, System.getProperty("user.dir"));
		myPythonInterpreter.exec("os.chdir(\"" + workingDir + "\")");
		logger.info("Executing {} ", pythonPyFile);
		myPythonInterpreter.execfile(pythonPyFile);

		// get function reference
		pyFunction = myPythonInterpreter.get(pythonMethodName);
		if (pyFunction == null)
			logger.error("Could not find Python function: " + pythonMethodName + " in Python program " + pythonPyFile);
		else
			logger.info("Done! Derived a reference to the python function " + pythonMethodName + " in " + pythonPyFile);

		myPythonInterpreter.close();
		this.scoreTable = loadScoreTable();
	}
	public CvssScoreCalculator() {
		this(new PythonInterpreter());
	}

	/**
	 * Get mean, minimum, maximum of the CVSS scores whose CVSS vector match with
	 * the provided partial CVSS vector
	 * 
	 * For more details about possible values of each of the AV, AC, PR, UI, S, C,
	 * I, A categories, please take a look at CVSS v3.1 calculator at
	 * https://www.first.org/cvss/calculator/3.1
	 * 
	 * To denote that a particular metric value is not specified in the input, use
	 * the letter 'X'.
	 * 
	 * @param partialCvssVector
	 * @return A list containing the mean, minimum, maximum of score of the matching
	 *         CVSS vectors
	 */
	public double[] getCvssScoreJython(String[] partialCvssVector) {

		// call function and get result
		PyList pyListCvss = new PyList(Arrays.asList(partialCvssVector));
		PyList result = (PyList) pyFunction.__call__(pyListCvss);
		Object[] objectArray = result.toArray();
		Double[] doubleArray = new Double[objectArray.length];
		System.arraycopy(objectArray, 0, doubleArray, 0, doubleArray.length);

		// calculate mean, minimum, maximum and standard deviation
		// double[] values = calculateMeanMinMaxStdDeviation(doubleArray);
		double[] values = calculateMedianMinMaxStdDeviation(doubleArray);


		return values;
	}

	/**
	 * Calculate mean, min, max of the provided CVSS scores
	 * 
	 * @param list
	 * @return An array containing three values
	 */
	private double[] calculateMean(Double[] list) {
		if (list.length == 0)
			return new double[] { -1, -1, -1 }; // don't divide by zero!
		double sum = 0;
		double min = list[0];
		double max = list[0];

		for (double val : list) {
			sum += val;
			if (val > max)
				max = val;
			if (val < min)
				min = val;
		}
		return new double[] { sum / list.length, min, max };
	}

	/**
	 * get median from a list of numbers
	 * 
	 * @param numList
	 * @return
	 */
	private double calculateMedian(Double[] numList) {
		Arrays.sort(numList);
		double median;
		if (numList.length % 2 == 0)
			median = (numList[numList.length / 2] + (double) numList[numList.length / 2 - 1]) / 2;
		else
			median = numList[numList.length / 2];
		return median;
	}

	/**
	 * 
	 * @param list
	 * @return
	 */
	public double[] calculateMedianMinMaxStdDeviation(Double[] list) {

		if (list.length == 0)
			return new double[] { -1, -1, -1, -1 };

		double sum = 0;
		double median = calculateMedian(list);
		double[] meanMinMax = calculateMean(list);
		double mean = meanMinMax[0];

		for (int i = 0; i < list.length; i++) {
			sum = sum + (list[i] - mean) * (list[i] - mean);
		}
		double squaredDiffMean = (sum) / (list.length);
		double standardDev = (Math.sqrt(squaredDiffMean));

		return new double[] { median, meanMinMax[1], meanMinMax[2], standardDev };
	}

	/**
	 * New (august 2023) way of computing cvss scores. The previous methodology would check a cvss vector against a large dataset and return the median matching score.
	 * This method loads a precomputed map from cvss vector -> score for a simple lookup instead.
	 * @return map from cvss vector to median score among matching NVD vulnerabilities
	 */
	private Map<CVSSVector, Double> loadScoreTable() {
		Map<CVSSVector, Double> out = new HashMap<>();
		Path mapPath = Paths.get(ReconcilerEnvVars.getDataDir(), "cvss", "cvss_map.csv");
		try (CSVReader reader = new CSVReader(new FileReader(mapPath.toFile()))) {
			String[] line;
			while ((line=reader.readNext()) != null) {
				out.put(new CVSSVector(line[0]), Double.parseDouble(line[1]));
			}
		} catch (IOException e) {
			logger.error("Error while loading CVSS score map");
			logger.error(e);
		}
		return out;
	}

	/**
	 * New (august 2023) way of computing cvss scores. The previous methodology would check a cvss vector against a large dataset and return the median matching score.
	 * @param cvssVector An array of symbols derived from VDO labels, see PartialCvssVectorGenerator.java
	 * @return the median score of all matching vulnerabilities in an NVD dataset
	 */
	public double lookupCvssScore(String[] cvssVector) {
		return this.scoreTable.get(new CVSSVector(cvssVector));
	}
}
