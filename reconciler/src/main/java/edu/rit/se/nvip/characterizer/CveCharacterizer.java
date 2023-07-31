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
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.CvssScore;
import edu.rit.se.nvip.model.VdoCharacteristic;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * 
 * @author axoeec
 *
 */
public class CveCharacterizer {
	private Logger logger = LogManager.getLogger(CveCharacterizer.class.getSimpleName());
	private List<AbstractCveClassifier> myClassifierList = new ArrayList<>();

	/**
	 * these two vars are used to derive the CVSS vector from VDO labels and then
	 * use the vector to derive the CVSS score
	 */
	private PartialCvssVectorGenerator partialCvssVectorGenerator = new PartialCvssVectorGenerator();
	private CvssScoreCalculator cvssScoreCalculator = new CvssScoreCalculator();

	public enum VDONounGroup{
		IMPACT_METHOD(1, "ImpactMethod", "Impact Method"),
		CONTEXT(2, "Context", "Context"),
		MITIGATION(3, "Mitigation", "Mitigation"),
		ATTACK_THEATER(4, "AttackTheater", "Attack Theater"),
		LOGICAL_IMPACT(5, "LogicalImpact", "Logical Impact");

		private int vdoNounGroupId;
		private String vdoNounGroupName;
		private String vdoNameForUI;

		VDONounGroup(int vdoNounGroupId, String vdoNounGroupName, String vdoNameForUI) {
			this.vdoNounGroupId = vdoNounGroupId;
			this.vdoNounGroupName = vdoNounGroupName;
			this.vdoNameForUI = vdoNameForUI;
		}
		public int getVdoGroupId() {
			return vdoNounGroupId;
		}
		public static VDONounGroup getVdoNounGroup(int vdoNounGroupId){
			for(VDONounGroup vdo : VDONounGroup.values()){
				if (vdoNounGroupId == vdo.getVdoGroupId()){
					return vdo;
				}
			}
			return null;
		}

	}

	public enum VDOLabel {
		TRUST_FAILURE(1, "Trust Failure", "Trust Failure", VDONounGroup.IMPACT_METHOD),
		MAN_IN_THE_MIDDLE(2, "Man-in-the-Middle", "Man-in-the-Middle", VDONounGroup.IMPACT_METHOD),
		CHANNEL(3, "Channel", "Channel", VDONounGroup.CONTEXT),
		AUTHENTICATION_BYPASS(4, "Authentication Bypass", "Authentication Bypass", VDONounGroup.IMPACT_METHOD),
		PHYSICAL_HARDWARE(5, "Physical Hardware", "Physical Hardware", VDONounGroup.CONTEXT),
		APPLICATION(6, "Application", "Application", VDONounGroup.CONTEXT),
		HOST_OS(7, "Host OS", "Host OS", VDONounGroup.CONTEXT),
		FIRMWARE(8, "Firmware", "Firmware", VDONounGroup.CONTEXT),
		CODE_EXECUTION(9, "Code Execution", "Code Execution", VDONounGroup.IMPACT_METHOD),
		CONTEXT_ESCAPE(10, "Context Escape", "Context Escape", VDONounGroup.IMPACT_METHOD),
		GUEST_OS(11, "Guest OS", "Guest OS", VDONounGroup.CONTEXT),
		HYPERVISOR(12, "Hypervisor", "Hypervisor", VDONounGroup.CONTEXT),
		SANDBOXED(13, "Sandboxed", "Sandboxed", VDONounGroup.MITIGATION),
		PHYSICAL_SECURITY(14, "Physical Security", "Physical Security", VDONounGroup.MITIGATION),
		ASLR(15, "ASLR", "ASLR", VDONounGroup.MITIGATION),
		LIMITED_RMT(16, "Limited Rmt", "Limited Rmt", VDONounGroup.ATTACK_THEATER),
		LOCAL(17, "Local", "Local", VDONounGroup.ATTACK_THEATER),
		READ(18, "Read", "Read", VDONounGroup.LOGICAL_IMPACT),
		RESOURCE_REMOVAL(19, "Resource Removal", "Resource Removal", VDONounGroup.LOGICAL_IMPACT),
		HPKP_HSTS(20, "HPKP/HSTS", "HPKP/HSTS", VDONounGroup.MITIGATION),
		MULTIFACTOR_AUTHENTICATION(21, "MultiFactor Authentication", "MultiFactor Authentication", VDONounGroup.MITIGATION),
		REMOTE(22, "Remote", "Remote", VDONounGroup.ATTACK_THEATER),
		WRITE(23, "Write", "Write", VDONounGroup.LOGICAL_IMPACT),
		INDIRECT_DISCLOSURE(24, "Indirect Disclosure", "Indirect Disclosure", VDONounGroup.LOGICAL_IMPACT),
		SERVICE_INTERRUPT(25, "Service Interrupt", "Service Interrupt", VDONounGroup.LOGICAL_IMPACT),
		PRIVILEGE_ESCALATION(26, "Privilege Escalation", "Privilege Escalation", VDONounGroup.LOGICAL_IMPACT),
		PHYSICAL(27, "Physical", "Physical", VDONounGroup.ATTACK_THEATER);

		private int vdoLabelId;
		private String vdoLabelName;
		private String vdoLabelForUI;
		private VDONounGroup vdoNounGroup;

		VDOLabel(int vdoLabelId, String vdoLabelName, String vdoLabelForUI, VDONounGroup vdoNounGroup) {
			this.vdoLabelId = vdoLabelId;
			this.vdoLabelName = vdoLabelName;
			this.vdoLabelForUI = vdoLabelForUI;
			this.vdoNounGroup = vdoNounGroup;
		}
		public int getVdoLabelId() {
			return vdoLabelId;
		}
		public static Integer getVdoLabelId(String vdoLabelName){
			for (VDOLabel label : VDOLabel.values()){
				if (label.vdoLabelName.equals(vdoLabelName)){
					return label.vdoLabelId;
				}
			}
			return null;
		}
		public static VDOLabel getVdoLabel(int vdoLabelId){
			for(VDOLabel vdo : VDOLabel.values()){
				if (vdoLabelId == vdo.getVdoLabelId()){
					return vdo;
				}
			}
			return null;
		}

	}
	public enum CVSSSeverity {
		HIGH(1),
		MEDIUM(2),
		NA(3),
		CRITICAL(4),
		LOW(5);

		private final int cvssSeverityId;


		CVSSSeverity(int cvssSeverityId) {
			this.cvssSeverityId = cvssSeverityId;
		}

		public int getCvssSeverityId() {
			return cvssSeverityId;
		}

		public static CVSSSeverity getCVSSSeverity(int cvssSeverityId){
			for(CVSSSeverity cvss : CVSSSeverity.values()){
				if (cvssSeverityId == cvss.getCvssSeverityId()){
					return cvss;
				}
			}
			return null;
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
		try {

			/**
			 * trainingDataPath may include multiple CSV files, if that is the case then
			 * train a model for each CSV file!
			 */

			String[] trainingDataFileArr = trainingDataFiles.split(",");
			for (String trainingDataFileName : trainingDataFileArr) {
				String vdoNounGroupName = trainingDataFileName.replace(".csv", "");
				trainingDataFileName = trainingDataPath + trainingDataFileName;
				// remove special chars?
				String sContent = FileUtils.readFileToString(new File(trainingDataFileName));
				sContent = sContent.replaceAll("[ '|\\\"|â€�|\\|]", " ");
				FileUtils.writeStringToFile(new File(trainingDataFileName), sContent, false);

				// pre-process training data and store it
				CvePreProcessor nvipPreProcessor = new CvePreProcessor(true);
				String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");
				String sCommaSeparatedAttribRows = nvipPreProcessor.preProcessFile(trainingDataFileName);

				FileUtils.writeStringToFile(new File(preProcessedTrainingDataFile), sCommaSeparatedAttribRows, false);
				logger.info("Raw training data at {} is processed and a CSV file is generated at {}", trainingDataFileName, preProcessedTrainingDataFile);

				// get CVE classification model
				CveClassifierFactory cveCharacterizerFactory = new CveClassifierFactory();
				AbstractCveClassifier aClassifier = cveCharacterizerFactory.getCveClassifier(approach, method, preProcessedTrainingDataFile);

				// assign a name to each classifier.
				aClassifier.setCveClassifierName(vdoNounGroupName);

				// train the model
				aClassifier.trainMLModel();
				myClassifierList.add(aClassifier);
			}

		} catch (Exception e) {
			logger.error("An error occurred while training a classifier for CVE Characterizer! NVIP will not crash but " +
					"CVE Characterizer will NOT work properly. Check your training data at {}\nException: {}",
					trainingDataPath, e.getMessage());
		}

	}

	/**
	 * Method overload!
	 * 
	 * @param cveDesc
	 * @param bPredictMultiple
	 * @return
	 */
	public Map<String, ArrayList<String[]>> characterizeCveForVDO(String cveDesc, boolean bPredictMultiple) {
		CvePreProcessor cvePreProcessor = new CvePreProcessor(true);
		String cveDescProcessed = cvePreProcessor.preProcessLine(cveDesc);

		Map<String, ArrayList<String[]>> prediction = new HashMap<String, ArrayList<String[]>>();
		for (AbstractCveClassifier aClassifier : myClassifierList) {
			ArrayList<String[]> predictionFromClassifier = aClassifier.predict(cveDescProcessed, bPredictMultiple);
			String vdoNounGroup = aClassifier.getCveClassifierName();
			prediction.put(vdoNounGroup, predictionFromClassifier);
		}

		return prediction;
	}

	/**
	 * Gets the data from the table as a Hashmap
	 * @param enums
	 * @return
	 */
	public Map<String, Integer> getTableDataAsHashMap(Enum<?>[] enums) {
		Map<String, Integer> dataMap = new HashMap<>();

		for (int i = 0; i < enums.length; i++) {
			int id = i + 1;
			String name = enums[i].name();
			dataMap.put(name, id);
		}

		return dataMap;
	}

	public Map<String, Integer> getCvssSeverityLabels() {
		return getTableDataAsHashMap(CVSSSeverity.values());
	}
	public Map<String, Integer> getVdoLabels() {
		return getTableDataAsHashMap(VDOLabel.values());
	}

	public Map<String, Integer> getVdoNounGroups() {
		return getTableDataAsHashMap(VDONounGroup.values());
	}

	/**
	 * characterize vulnerabilities in the given <cveList>
	 * 
	 * @param cveList
	 */
	public List<CompositeVulnerability> characterizeCveList(List<CompositeVulnerability> cveList, int limit) {

		long start = System.currentTimeMillis();
		int totCharacterized = 0;

		Map<String, Integer> cvssSeverityLabels = getCvssSeverityLabels();
		Map<String, Integer> vdoLabels = getVdoLabels();
		Map<String, Integer> vdoNounGroups = getVdoNounGroups();

		int countNotChanged = 0;
		int countBadDescription = 0;

		// predict for each CVE, the model was trained in the constructor!
		for (int i = 0; i < cveList.size(); i++) {
			CompositeVulnerability vulnerability = null;
			/**
			 * To skip the rest of the characterization for the very first run or if the
			 * system has not been run for a long time. The process could be time consuming
			 * for too many CVEs
			 */
			if (totCharacterized > limit)
				break;

			try {
				vulnerability = cveList.get(i);
				String cveDesc = vulnerability.getDescription();
				if (cveDesc == null || cveDesc.length() < 50) {
					if (cveDesc.length() > 1 && cveDesc.length() < 50)
						logger.warn("WARNING: Description too small for {} at {}. Desc: {}",
								vulnerability.getCveId(),
								vulnerability.getSourceURLs(),
								cveDesc);
					else
						logger.warn("WARNING: BAD or MISSING Description '{}' for {} at {}",
								cveDesc,
								vulnerability.getCveId(),
								vulnerability.getSourceURLs());
					countBadDescription++;
					continue; // if no description or old CVE skip!
				}
				if (vulnerability.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UNCHANGED) {
					//logger.info("No change in description for Characterization of {}", cveDesc);
					countNotChanged++;
					continue; // the same CVE in db
				}
				
				// characterize CVE
				Map<String, ArrayList<String[]>> prediction = characterizeCveForVDO(cveDesc, true);
				for (VDONounGroup vdoNounGroup : VDONounGroup.values()) {
					ArrayList<String[]> predictionsForNounGroup = prediction.get(vdoNounGroup.vdoNounGroupName);
					int vdoNounGroupId = vdoNounGroup.vdoNounGroupId;
//					if (vdoNounGroupId == null) {
//						logger.warn("WARNING: No entry was found for vdo noun group: {}! Please add it to the db.", vdoNounGroup);
//						continue;
//					}
					for (String[] item : predictionsForNounGroup) {
						Integer vdoLabelId = VDOLabel.getVdoLabelId(item[0]);
						if (vdoLabelId == null)
							logger.warn("WARNING: No entry was found for vdo noun group label: {}! Please add it to the db", vdoLabelId);
						else {
							VdoCharacteristic vdoCharacteristic = new VdoCharacteristic(vulnerability.getCveId(), vdoLabelId,
									Double.parseDouble(item[1]), vdoNounGroupId);
							vulnerability.addVdoCharacteristic(vdoCharacteristic);
							//logger.info("Added the following VDO Characteristic to {}:\n{}", vulnerability.getCveId(), vdoCharacteristic);
						}
					}
					//logger.info("Added VDO Characteristics for {}", vulnerability.getCveId());
				}

				// get severity
				double[] cvssScore = getCvssScoreFromVdoLabels(prediction); // get mean/minimum/maximum/std dev
				Integer severityId = cvssSeverityLabels.get(getSeverityLabelFromCvssScore(cvssScore[0])); // use mean
				if (severityId == null)
					logger.warn("WARNING: No entry was found for severity class {}! Please add it to the db.", severityId);
				else {
					CvssScore score = new CvssScore(vulnerability.getCveId(), severityId, 0.5, String.valueOf(cvssScore[0]), 0.5);
					vulnerability.addCvssScore(score);
//					logger.info("CVSS Score predicted for {}", vulnerability.getCveId());
				}

				// update list
				cveList.set(i, vulnerability);

				// log
				if (totCharacterized % 100 == 0 && totCharacterized > 0) {
					double percent = (totCharacterized + countBadDescription + countNotChanged) * 1.0 / cveList.size() * 100;
					logger.info("Characterized {} of {} total CVEs. Skipping {} CVEs: \n[{} bad/null and {} not changed descriptions], {}% done! ", totCharacterized, cveList.size(),
							(countBadDescription + countNotChanged), countBadDescription, countNotChanged, Math.round(percent));
				}
			} catch (Exception e) {
				logger.error("ERROR: Failure during characterization of CVE: {}\n{}", vulnerability.getCveId(), e);
			}

			totCharacterized++;
		} // for
		long seconds = (System.currentTimeMillis() - start) / 1000;
		double avgTime = seconds * 1.0 / totCharacterized;
		logger.info("***Characterized {} of total {} CVEs in {} seconds! Avg time(s): {}", totCharacterized, cveList.size(), seconds, avgTime);
		logger.info("{} CVEs did not have a good description, and {} CVEs had the same description (after reconciliation) and skipped!", countBadDescription, countNotChanged);

		return cveList;
	}

	/**
	 * get VDO labels and return a double array that includes the
	 * mean/minimum/maximum and standard deviation of the CVSS scores in NVD
	 * matching with these labels
	 * 
	 * @param predictionsForVuln
	 * @return
	 */
	private double[] getCvssScoreFromVdoLabels(Map<String, ArrayList<String[]>> predictionsForVuln) {
		// generate partial CVSS vector from VDO prediction
		String[] cvssVec = partialCvssVectorGenerator.getCVssVector(predictionsForVuln);

		// get CVSS mean/min/max/std dev from Python script
		return cvssScoreCalculator.getCvssScoreJython(cvssVec);
	}

	private String getSeverityLabelFromCvssScore(double cvssScore) {
		String severityLabel;
		if (cvssScore < 4)
			severityLabel = "LOW";
		else if (cvssScore <= 6.5)
			severityLabel = "MEDIUM";
		else if (cvssScore < 9)
			severityLabel = "HIGH";
		else
			severityLabel = "CRITICAL";
		return severityLabel;
	}

}
