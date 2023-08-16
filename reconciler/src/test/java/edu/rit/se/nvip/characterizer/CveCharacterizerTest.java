package edu.rit.se.nvip.characterizer;
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

import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.automatedcvss.CvssScoreCalculator;
import edu.rit.se.nvip.automatedcvss.PartialCvssVectorGenerator;
import edu.rit.se.nvip.automatedcvss.preprocessor.CvePreProcessor;
import edu.rit.se.nvip.characterizer.classifier.AbstractCveClassifier;
import edu.rit.se.nvip.characterizer.classifier.CveClassifierFactory;
import edu.rit.se.nvip.characterizer.enums.CVSSSeverityClass;
import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import oshi.util.FileUtil;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;
import java.nio.file.Paths;
import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;


public class CveCharacterizerTest {

	private Logger logger = LogManager.getLogger(CveCharacterizerTest.class.getSimpleName());
	@PrepareForTest({ FileUtils.class })
	@Test
	public void testCveCharacterization() throws NoSuchFieldException, IllegalAccessException, IOException {
		MockedStatic<FileUtils> mocked = mockStatic(FileUtils.class);
		MockedStatic<CVSSSeverityClass> mockedCvss = mockStatic(CVSSSeverityClass.class);

		CvePreProcessor mockPreProcessor = mock(CvePreProcessor.class);
		CveClassifierFactory mockCveClassifierFactory = mock(CveClassifierFactory.class);
		AbstractCveClassifier mockAbstractCveClassifier = mock(AbstractCveClassifier.class);
		PartialCvssVectorGenerator mockVectorGenerator = mock(PartialCvssVectorGenerator.class);
		CvssScoreCalculator mockScoreCalculator = mock(CvssScoreCalculator.class);

		doNothing().when(FileUtils.class);
		FileUtils.writeStringToFile(any(File.class), anyString(), anyBoolean());
		mocked.when(() -> FileUtils.readFileToString(any(File.class))).thenReturn("{ \"key\": \"value\"}");
		when(mockPreProcessor.preProcessFile(anyString())).thenReturn(anyString());
		when(mockPreProcessor.preProcessLine("test")).thenReturn(anyString());
		when(mockCveClassifierFactory.getCveClassifier("test", anyString(), anyString())).thenReturn(mockAbstractCveClassifier);
		mockedCvss.when(() -> CVSSSeverityClass.getCVSSSeverityByScore(anyDouble())).thenReturn(any(CVSSSeverityClass.class));



		String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
		// test prediction
		String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";

		CveCharacterizer cveCharacterizer = new CveCharacterizer(
				mockPreProcessor, mockCveClassifierFactory, mockScoreCalculator, mockVectorGenerator,
				trainingDataInfo[0], trainingDataInfo[1], "ML", "NB");

		//Test characterizeCveForVDO
		Map<VDONounGroup,Map<VDOLabel, Double>> prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, true);
		assertTrue(prediction.size() > 0);

		prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, false);
		assertTrue(prediction.size() > 0);
		//String csvPath = "src/test/resources/test-composite-vuln-list.csv";
		//String csvPath = System.getProperty("user.dir") + "\\src\\main\\resources\\cvedata\\mitre-cve.csv";
		String csvPath = Paths.get("src","test","resources", "cvedata", "mitre-cve.csv").toAbsolutePath().toString();

		CsvUtils utils = new CsvUtils();
		List<String[]> data = utils.getDataFromCsv(csvPath);
		List<String[]> testData = new LinkedList<>();
		for (int i = 0; i < 10; i++) {
			testData.add(data.get(i));
		}
		// generate vuln list
		List<CompositeVulnerability> vulnList = new ArrayList<>();
		int i = 0;
		for (String[] line : testData) {
			String cveId = line[0];
			String description = line[1];
			if (description.contains("** RESERVED") || description.contains("** REJECT"))
				continue;
			CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(i++, cveId, description, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), ""));

			vulnList.add(vuln);

		}

		List<CompositeVulnerability> newList = cveCharacterizer.characterizeCveList(vulnList, 5000);

		assertEquals(10, newList.size());

		mocked.close();
		mockedCvss.close();


	}
}

