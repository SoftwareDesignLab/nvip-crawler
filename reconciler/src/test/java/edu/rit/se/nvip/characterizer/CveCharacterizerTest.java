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

package edu.rit.se.nvip.characterizer;
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

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.rit.se.nvip.automatedcvss.CvssScoreCalculator;
import edu.rit.se.nvip.automatedcvss.PartialCvssVectorGenerator;
import edu.rit.se.nvip.automatedcvss.preprocessor.CvePreProcessor;
import edu.rit.se.nvip.characterizer.classifier.CveClassifierFactory;
import edu.rit.se.nvip.characterizer.classifier.OrdinaryCveClassifier;
import edu.rit.se.nvip.db.model.enums.VDOLabel;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.db.model.SSVC;
import edu.rit.se.nvip.db.repositories.CharacterizationRepository;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.net.URL;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.nio.file.Paths;
import java.io.File;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class CveCharacterizerTest {

	@Test
	public void testCveCharacterization() {
		//mocks
		MockedStatic<FileUtils> mockedUtils = mockStatic(FileUtils.class);
		CvePreProcessor mockPreProcessor = mock(CvePreProcessor.class);
		CveClassifierFactory mockCveClassifierFactory = mock(CveClassifierFactory.class);
		CvssScoreCalculator mockCvssScoreCalculator = mock(CvssScoreCalculator.class);
		PartialCvssVectorGenerator mockPartialCvssVectorGenerator = mock(PartialCvssVectorGenerator.class);
		OrdinaryCveClassifier mockClassifier = mock(OrdinaryCveClassifier.class);
		String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
		//dummy predictions
		ArrayList<String[]> dummyPredictions = new ArrayList<>();
		dummyPredictions.add(new String[]{"Local", "0.8"});
		dummyPredictions.add(new String[]{"Read", "0.1"});
		dummyPredictions.add(new String[]{"Remote", "2.1"});
		dummyPredictions.add(new String[]{"Write", "1.4"});
		dummyPredictions.add(new String[]{"Privilege Escalation", "1.5"});
		dummyPredictions.add(new String[]{"Physical", "1.0"});
		double[] dummyDoubles = {2.0, 1.0, 3.0, 1.0};
		// test prediction
		String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";
		//mock actual calls
		when(mockPreProcessor.preProcessFile(anyString())).thenReturn("mocked, content");
		when(mockPreProcessor.preProcessLine(anyString())).thenReturn("mocked, content");
		when(mockCveClassifierFactory.getCveClassifier(anyString(), anyString(), anyString())).thenReturn(mockClassifier);
		doNothing().when(mockClassifier).setCveClassifierName(anyString());
		doNothing().when(mockClassifier).trainMLModel();
		mockedUtils.when(() -> FileUtils.readFileToString(any(File.class))).thenReturn("{\"key\" : \"value\"}");
		mockedUtils.when(() -> FileUtils.writeStringToFile(any(File.class), anyString(), anyBoolean())).thenAnswer((Answer<Void>) invocation -> null);
		when(mockClassifier.predict(anyString(), anyBoolean())).thenReturn(dummyPredictions);
		when(mockPartialCvssVectorGenerator.getCVssVector(anySet())).thenReturn(new String[8]);
		//create characterizer with the mocks manually injected
		CveCharacterizer cveCharacterizer = new CveCharacterizer(mockPreProcessor, mockCveClassifierFactory, mockCvssScoreCalculator, mockPartialCvssVectorGenerator,
				trainingDataInfo[0], trainingDataInfo[1], "ML", "NB", null); // TODO: Add/mock dbh



		//Test characterizeCveForVDO
		Map<VDOLabel, Double> prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, true);
		assertTrue(prediction.size() > 0);

		prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, false);
		assertTrue(prediction.size() > 0);

		String csvPath = Paths.get("src","test","resources", "cvedata", "mitre-cve.csv").toAbsolutePath().toString();

		CsvUtils utils = new CsvUtils();
		List<String[]> data = utils.getDataFromCsv(csvPath);
		List<String[]> testData = new LinkedList<>();
		for (int i = 0; i < 10; i++) {
			testData.add(data.get(i));
		}
		// generate vuln list
		Set<CompositeVulnerability> vulnSet = new HashSet<>();
		for (String[] line : testData) {
			String cveId = line[0];
			String description = line[1];
			if (description.contains("** RESERVED") || description.contains("** REJECT"))
				continue;
			CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, cveId, description, null, null, null, ""));

			vulnSet.add(vuln);
		}

		//added 2 vulns with null desc and short desc to reach more code coverage
		CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, "cve-1", null, null, null, null, ""));
		vuln.setPotentialSources(new HashSet<>());
		CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(1, "cve-1", "short desc",	null, null, null, ""));
		vuln2.setPotentialSources(new HashSet<>());
		vulnSet.add(vuln);
		vulnSet.add(vuln2);

		cveCharacterizer.characterizeCveList(vulnSet, 5000);
		assertEquals(12, vulnSet.size());

		mockedUtils.close();
	}

	@Nested
	public class CharacterizeCveListTests {

		@Test
		void itCallsSSVCApi(){
			//mocks
			MockedStatic<FileUtils> mockedUtils = mockStatic(FileUtils.class);
			CvePreProcessor mockPreProcessor = mock(CvePreProcessor.class);
			CveClassifierFactory mockCveClassifierFactory = mock(CveClassifierFactory.class);
			CvssScoreCalculator mockCvssScoreCalculator = mock(CvssScoreCalculator.class);
			PartialCvssVectorGenerator mockPartialCvssVectorGenerator = mock(PartialCvssVectorGenerator.class);
			OrdinaryCveClassifier mockClassifier = mock(OrdinaryCveClassifier.class);
			String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
			//dummy predictions
			ArrayList<String[]> dummyPredictions = new ArrayList<>();
			dummyPredictions.add(new String[]{"Local", "0.8"});
			dummyPredictions.add(new String[]{"Read", "0.1"});
			dummyPredictions.add(new String[]{"Remote", "2.1"});
			dummyPredictions.add(new String[]{"Write", "1.4"});
			dummyPredictions.add(new String[]{"Privilege Escalation", "1.5"});
			dummyPredictions.add(new String[]{"Physical", "1.0"});
			double[] dummyDoubles = {2.0, 1.0, 3.0, 1.0};
			// test prediction
			String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";
			//mock actual calls
			when(mockPreProcessor.preProcessFile(anyString())).thenReturn("mocked, content");
			when(mockPreProcessor.preProcessLine(anyString())).thenReturn("mocked, content");
			when(mockCveClassifierFactory.getCveClassifier(anyString(), anyString(), anyString())).thenReturn(mockClassifier);
			doNothing().when(mockClassifier).setCveClassifierName(anyString());
			doNothing().when(mockClassifier).trainMLModel();
			mockedUtils.when(() -> FileUtils.readFileToString(any(File.class))).thenReturn("{\"key\" : \"value\"}");
			mockedUtils.when(() -> FileUtils.writeStringToFile(any(File.class), anyString(), anyBoolean())).thenAnswer((Answer<Void>) invocation -> null);
			when(mockClassifier.predict(anyString(), anyBoolean())).thenReturn(dummyPredictions);
			when(mockPartialCvssVectorGenerator.getCVssVector(anySet())).thenReturn(new String[8]);
			//create characterizer with the mocks manually injected
			CveCharacterizer cveCharacterizer = new CveCharacterizer(mockPreProcessor, mockCveClassifierFactory, mockCvssScoreCalculator, mockPartialCvssVectorGenerator,
					trainingDataInfo[0], trainingDataInfo[1], "ML", "NB", mock(CharacterizationRepository.class)); // TODO: Add/mock dbh


			CompositeVulnerability vulnerability = new CompositeVulnerability(new RawVulnerability(1, "CVE-1234-5678", "Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.", null, null, null, ""));
			vulnerability.setPotentialSources(new HashSet<>());

			cveCharacterizer.setSSVCApiBaseUrl("http://test.host");

			ObjectMapper om = mock(ObjectMapper.class);
			try {
				when(om.readValue(any(URL.class), eq(SSVC.class))).thenReturn(new SSVC());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			cveCharacterizer.setObjectMapper(om);

			cveCharacterizer.characterizeCveList(Set.of(vulnerability), 100);

			try {
				verify(om, times(1)).readValue(
						eq(new URL(String.format(
								"http://test.host:5000/ssvc?exploitStatus=%s&cveId=%s&description=%s",
								"NONE",
								vulnerability.getCveId(),
								"Buffer+overflow+in+NFS+mountd+gives+root+access+to+remote+attackers%2C+mostly+in+Linux+systems."
						))),
						eq(SSVC.class));
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

	}
}