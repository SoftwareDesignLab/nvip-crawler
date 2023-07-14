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
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import org.mockito.MockedConstruction;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.nio.file.Paths;
import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mockConstruction;

public class CveCharacterizerTest {

	@Test
	public void testCveCharacterization() {
		String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
		// test prediction
		String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";

		CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataInfo[0], trainingDataInfo[1], "ML", "NB");

		//Test characterizeCveForVDO
		Map<String,ArrayList<String[]>> prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, true);
		assertTrue(prediction.size() > 0);

		prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, false);
		assertTrue(prediction.size() > 0);
		try(MockedConstruction<DatabaseHelper> mock = mockConstruction(DatabaseHelper.class)){
			//String csvPath = "src/test/resources/test-composite-vuln-list.csv";
			//String csvPath = System.getProperty("user.dir") + "\\src\\main\\resources\\cvedata\\mitre-cve.csv";
                        String csvPath = Paths.get("src","test","resources", "cvedata", "mitre-cve.csv").toAbsolutePath().toString();
                        Logger logger = LogManager.getLogger(getClass().getSimpleName());
			logger.info(System.getProperty("user.dir"));
                        logger.info(new File(Paths.get("src","test","resources", "cvedata", "mitre-cve.csv").toUri()).exists());

			CsvUtils utils = new CsvUtils();
			List<String[]> data = utils.getDataFromCsv(csvPath);
			List<String[]> testData = new LinkedList<>();
			for (int i = 0; i < 10; i++) {
				testData.add(data.get(i));
			}
			// generate vuln list
			List<CompositeVulnerability> vulnList = new ArrayList<>();
			for (String[] line : testData) {
				String cveId = line[0];
				String description = line[1];
				if (description.contains("** RESERVED") || description.contains("** REJECT"))
					continue;
				CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, cveId, description, null, null, null, ""));

				vulnList.add(vuln);
			}

			List<CompositeVulnerability> newList = cveCharacterizer.characterizeCveList(vulnList, 5000);
			assertEquals(10, newList.size());

		}

	}
}
