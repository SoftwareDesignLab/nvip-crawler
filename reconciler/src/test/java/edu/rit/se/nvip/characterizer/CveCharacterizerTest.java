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
import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.CsvUtils;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import org.mockito.MockedConstruction;

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

	@Test
	public void testCveCharacterization() {
		CveCharacterizer mockCveCharacterizer = mock(CveCharacterizer.class);
		Map<VDONounGroup, Map<VDOLabel, Double>> map = new HashMap<>();
		map.put(VDONounGroup.CONTEXT, new HashMap<>());
		List<CompositeVulnerability> mockList = new ArrayList<>();
		mockList.add(new CompositeVulnerability(new RawVulnerability(1, "cve-1",
				"The ntpd_driver component before 1.3.0 and 2.x before 2.2.0 for Robot Operating System (ROS) allows attackers, " +
						"who control the source code of a different node in the same ROS application, to change a robot's behavior. " +
						"This occurs because a topic name depends on the attacker-controlled time_ref_topic parameter.",
				new Timestamp(System.currentTimeMillis()),
				new Timestamp(System.currentTimeMillis()),
				new Timestamp(System.currentTimeMillis()),
				"www.example.com")));

		when(mockCveCharacterizer.characterizeCveForVDO(anyString(), anyBoolean())).thenReturn(map);
		when(mockCveCharacterizer.characterizeCveList(anyList(), anyInt())).thenReturn(mockList);

		String[] trainingDataInfo = {ReconcilerEnvVars.getTrainingDataDir(), ReconcilerEnvVars.getTrainingData()};
		// test prediction
		String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";

		//Test characterizeCveForVDO
		Map<VDONounGroup,Map<VDOLabel, Double>> prediction = mockCveCharacterizer.characterizeCveForVDO(cveDesc, true);
		assertTrue(prediction.size() > 0);

		prediction = mockCveCharacterizer.characterizeCveForVDO(cveDesc, false);
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
		for (String[] line : testData) {
			String cveId = line[0];
			String description = line[1];
			if (description.contains("** RESERVED") || description.contains("** REJECT"))
				continue;
			CompositeVulnerability vuln = new CompositeVulnerability(new RawVulnerability(1, cveId, description, null, null, null, ""));

			vulnList.add(vuln);
		}

		List<CompositeVulnerability> newList = mockCveCharacterizer.characterizeCveList(vulnList, 5000);
		assertEquals(1, newList.size());



	}
}
