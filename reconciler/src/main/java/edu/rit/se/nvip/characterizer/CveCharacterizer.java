package edu.rit.se.nvip.characterizer; /**
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

import edu.rit.se.nvip.automatedcvss.CvssScoreCalculator;
import edu.rit.se.nvip.automatedcvss.PartialCvssVectorGenerator;
import edu.rit.se.nvip.automatedcvss.preprocessor.CvePreProcessor;
import edu.rit.se.nvip.characterizer.classifier.AbstractCveClassifier;
import edu.rit.se.nvip.characterizer.classifier.CveClassifierFactory;
import edu.rit.se.nvip.characterizer.enums.CVSSSeverityClass;
import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.CvssScore;
import edu.rit.se.nvip.model.VdoCharacteristic;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.nio.file.Paths;
import java.util.*;


/**
 * 
 * @author axoeec
 *
 */
public class CveCharacterizer {
	private Logger logger = LogManager.getLogger(CveCharacterizer.class.getSimpleName());
	private final Map<VDONounGroup, AbstractCveClassifier> nounGroupToClassifier = new HashMap<>();

	/**
	 * these two vars are used to derive the CVSS vector from VDO labels and then
	 * use the vector to derive the CVSS score
	 */
	private PartialCvssVectorGenerator partialCvssVectorGenerator;
	private CvssScoreCalculator cvssScoreCalculator;
	private CvePreProcessor cvePreProcessor;

	/**
	 * Construct a CVE Characterizer. You need to provide an initial training data
	 * as CSV. No incremental training this time.
	 * @param cvePreProcessor
	 * @param cveClassifierFactory
	 * @param trainingDataPath
	 * @param trainingDataFiles
	 * @param approach
	 * @param method
	 */
	public CveCharacterizer(CvePreProcessor cvePreProcessor,
							CveClassifierFactory cveClassifierFactory,
							CvssScoreCalculator cvssScoreCalculator,
							PartialCvssVectorGenerator partialCvssVectorGenerator,
							String trainingDataPath, String trainingDataFiles, String approach, String method) {
		this.cvssScoreCalculator = cvssScoreCalculator;
		this.partialCvssVectorGenerator = partialCvssVectorGenerator;
		this.cvePreProcessor = cvePreProcessor;
		try {

			/**
			 * trainingDataPath may include multiple CSV files, if that is the case then
			 * train a model for each CSV file!
			 */

			String[] trainingDataFileArr = trainingDataFiles.split(",");
			for (String trainingDataFileName : trainingDataFileArr) {
				String vdoNounGroupName = trainingDataFileName.replace(".csv", "");
				VDONounGroup vdoNounGroup = VDONounGroup.getVdoNounGroup(vdoNounGroupName);
				trainingDataFileName = Paths.get(trainingDataPath).resolve(trainingDataFileName).toString();

				// remove special chars?
				String sContent = FileUtils.readFileToString(new File(trainingDataFileName));
				sContent = sContent.replaceAll("[ '|\\\"|â€�|\\|]", " ");
				FileUtils.writeStringToFile(new File(trainingDataFileName), sContent, false);
				// pre-process training data and store it
				String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
				String sCommaSeparatedAttribRows = cvePreProcessor.preProcessFile(trainingDataFileName);

				FileUtils.writeStringToFile(new File(preProcessedTrainingDataFile), sCommaSeparatedAttribRows, false);
				logger.info("Raw training data at {} is processed and a CSV file is generated at {}", trainingDataFileName, preProcessedTrainingDataFile);

				// get CVE classification model
				AbstractCveClassifier aClassifier = cveClassifierFactory.getCveClassifier(approach, method, preProcessedTrainingDataFile);

				// assign a noun group to each classifier
				aClassifier.setCveClassifierName(vdoNounGroupName);

				// train the model
				aClassifier.trainMLModel();
				nounGroupToClassifier.put(vdoNounGroup, aClassifier);


			}

		} catch (Exception e) {
			logger.error("An error occurred while training a classifier for CVE Characterizer! NVIP will not crash but CVE Characterizer will NOT work properly. Check your training data at {}\nException: {}", trainingDataPath, e.getMessage());
		}
	}

	
	/**
	 * Construct a CVE Characterizer. You need to provide an initial training data
	 * as CSV. No incremental training this time.
	 * 
	 * @param trainingDataPath
	 * @param trainingDataFiles
	 * @param approach
	 * @param method
	 //* @param loadSerializedModels
	 */

	//removed  boolean loadSerializedModels as well as exploitability package
	public CveCharacterizer(String trainingDataPath, String trainingDataFiles, String approach, String method) {
		this(new CvePreProcessor(true), new CveClassifierFactory(), new CvssScoreCalculator(), new PartialCvssVectorGenerator(), trainingDataPath, trainingDataFiles, approach, method);
	}

	/**
	 * Method overload!
	 * 
	 * @param cveDesc
	 * @param bPredictMultiple
	 * @return
	 */
	public Map<VDOLabel, Double> characterizeCveForVDO(String cveDesc, boolean bPredictMultiple) {
		String cveDescProcessed = cvePreProcessor.preProcessLine(cveDesc);

		Map<VDOLabel, Double> prediction = new HashMap<>();
		for (VDONounGroup nounGroup : nounGroupToClassifier.keySet()) {
			AbstractCveClassifier aClassifier = nounGroupToClassifier.get(nounGroup);
			ArrayList<String[]> predictionFromClassifier = aClassifier.predict(cveDescProcessed, bPredictMultiple);
			for (String[] pred : predictionFromClassifier) {
				VDOLabel label = VDOLabel.getVdoLabel(pred[0]);
				prediction.put(label, Double.parseDouble(pred[1]));
			}
		}
		return prediction;
	}

	/**
	 * characterize vulnerabilities in the given <cveList>
	 * 
	 * @param cveSet
	 */
	public void characterizeCveList(Set<CompositeVulnerability> cveSet, int limit) {

		long start = System.currentTimeMillis();
		int totCharacterized = 0;

		int countNotChanged = 0;
		int countBadDescription = 0;

		// predict for each CVE, the model was trained in the constructor!
		for (CompositeVulnerability vuln : cveSet) {
			/**
			 * To skip the rest of the characterization for the very first run or if the
			 * system has not been run for a long time. The process could be time consuming
			 * for too many CVEs
			 */
			if (totCharacterized > limit)
				break;

			try {
				if (vuln.getDescription() == null || vuln.getDescription().length() < 50) {
					countBadDescription++;
					logger.warn("WARNING: BAD or SHORT Description '{}' for {} at {}, skipping characterization", vuln.getDescription(), vuln.getCveId(), vuln.getSourceURLs());
					continue;
				}
				if (vuln.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UNCHANGED) {
					logger.info("Vulnerability {} was unchanged during reconciliation and is skipping characterization", vuln.getCveId());
					countNotChanged++;
					continue;
				}

				// TODO: Integrate SSVC scoring here

				// characterize CVE
				Map<VDOLabel, Double> prediction = characterizeCveForVDO(vuln.getDescription(), true);
				for (VDOLabel label : prediction.keySet()) {
					VdoCharacteristic vdoCharacteristic = new VdoCharacteristic(vuln.getCveId(), label, prediction.get(label));
					vuln.addVdoCharacteristic(vdoCharacteristic);
					logger.info("Added the following VDO Characteristic to {}:\n{}", vuln.getCveId(), vdoCharacteristic);
				}

				// get severity
				double cvssScore = getCvssScoreFromVdoLabels(prediction.keySet());
				CvssScore score = new CvssScore(vuln.getCveId(), cvssScore, 0.5); //confidence isn't used or stored anywhere
				vuln.addCvssScore(score);
//				logger.info("CVSS Score predicted for {}", vulnerability.getCveId());

				// log
				if (totCharacterized % 100 == 0 && totCharacterized > 0) {
					double percent = (totCharacterized + countBadDescription + countNotChanged) * 1.0 / cveSet.size() * 100;
					logger.info("Characterized {} of {} total CVEs. Skipping {} CVEs: \n[{} bad/null and {} not changed descriptions], {}% done! ", totCharacterized, cveSet.size(),
							(countBadDescription + countNotChanged), countBadDescription, countNotChanged, Math.round(percent));
				}
			} catch (Exception e) {
				logger.error("ERROR: Failure during characterization of CVE: {}\n{}", vuln.getCveId(), e);
			}

			totCharacterized++;
		} // for
		long seconds = (System.currentTimeMillis() - start) / 1000;
		double avgTime = seconds * 1.0 / totCharacterized;
		logger.info("***Characterized {} of total {} CVEs in {} seconds! Avg time(s): {}", totCharacterized, cveSet.size(), seconds, avgTime);
		logger.info("{} CVEs did not have a good description, and {} CVEs had the same description (after reconciliation) and skipped!", countBadDescription, countNotChanged);
	}

	/**
	 * get VDO labels and return a double array that includes the
	 * mean/minimum/maximum and standard deviation of the CVSS scores in NVD
	 * matching with these labels
	 * 
	 * @param predictionsForVuln
	 * @return
	 */
	private double getCvssScoreFromVdoLabels(Set<VDOLabel> predictionsForVuln) {
		// generate partial CVSS vector from VDO prediction
		String[] cvssVec = partialCvssVectorGenerator.getCVssVector(predictionsForVuln);

		// get CVSS median/min/max/std dev from Python script, return median
		// return cvssScoreCalculator.getCvssScoreJython(cvssVec)[0]; // old way of doing it
		return cvssScoreCalculator.lookupCvssScore(cvssVec); // should return same number as the old way but doesn't rely on python
	}
}
