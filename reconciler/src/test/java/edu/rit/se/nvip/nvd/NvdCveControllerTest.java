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

package edu.rit.se.nvip.nvd;

import edu.rit.se.nvip.db.repositories.NvdMitreRepository;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.NvdVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class NvdCveControllerTest {

    private NvdCveController nvdCveController;
    @Mock
    NvdMitreRepository mockDbh = mock(NvdMitreRepository.class);
    //verifies compare with Nvd properly compares Nvd vulns
    @Test
    void compareWithNvd() throws IOException {

        nvdCveController = new NvdCveController();

        nvdCveController.setDbRepo(mockDbh);

        Set<CompositeVulnerability> reconciledVulns = new HashSet<>();
        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2021-123455", "Description", null, null, null, ""));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(2, "CVE-2021-12234", "Description", null, null, null, ""));
        CompositeVulnerability vuln3 = new CompositeVulnerability(new RawVulnerability(3, "CVE-2021-12134", "Description", null, null, null, ""));
        CompositeVulnerability vuln4 = new CompositeVulnerability(new RawVulnerability(4, "CVE-2021-1", "Description", null, null, null, ""));
        CompositeVulnerability vuln5 = new CompositeVulnerability(new RawVulnerability(4, "CVE-2021-12", "Description", null, null, null, ""));
        reconciledVulns.add(vuln1);
        reconciledVulns.add(vuln2);
        reconciledVulns.add(vuln3);
        reconciledVulns.add(vuln4);
        reconciledVulns.add(vuln5);

        NvdVulnerability nvdVuln1 = new NvdVulnerability("CVE-2021-123455", new Timestamp(System.currentTimeMillis()), "Analyzed", new ArrayList<>());
        NvdVulnerability nvdVuln2 = new NvdVulnerability("CVE-2021-12234", new Timestamp(System.currentTimeMillis()), "Received", new ArrayList<>());
        NvdVulnerability nvdVuln3 = new NvdVulnerability("CVE-2021-12134", new Timestamp(System.currentTimeMillis()), "Undergoing Analysis", new ArrayList<>());
        NvdVulnerability nvdVuln4 = new NvdVulnerability("CVE-2021-1", new Timestamp(System.currentTimeMillis()), "Awaiting Analysis", new ArrayList<>());
        NvdVulnerability nvdVuln5 = new NvdVulnerability("CVE-2021-12", new Timestamp(System.currentTimeMillis()), "Not in NVD", new ArrayList<>());
        vuln1.setNvdVuln(nvdVuln1);
        vuln2.setNvdVuln(nvdVuln2);
        vuln3.setNvdVuln(nvdVuln3);
        vuln4.setNvdVuln(nvdVuln4);
        vuln5.setNvdVuln(nvdVuln5);

        when(mockDbh.attachNvdVulns(any())).thenReturn(reconciledVulns);

        nvdCveController.compareWithNvd(reconciledVulns);

        verify(mockDbh).attachNvdVulns(any());

        //Output should be 1 in Nvd 4 not in NVD 1 analyzed 1 received 1 undergoing analysis 1 awaiting analysis
        //current structure says on ANALYZED Nvd Vulns are considered in Nvd
    }

    //verifies update Nvd tables works, mocked Dbh
    @Test
    void updateNvdTables() throws IOException {
        nvdCveController = new NvdCveController();
        BufferedReader mockBR = mock(BufferedReader.class);
        URL mockURL = mock(URL.class);
        HttpURLConnection mockConn = mock(HttpURLConnection.class);
        InputStream mockInput = mock(InputStream.class);
        when(mockURL.openConnection()).thenReturn(mockConn);
        doNothing().when(mockConn).setRequestMethod(anyString());
        doNothing().when(mockConn).setRequestProperty(anyString(), anyString());
        when(mockConn.getResponseCode()).thenReturn(200);
        when(mockConn.getInputStream()).thenReturn(mockInput);
        doNothing().when(mockConn).disconnect();
        nvdCveController.setBr(mockBR);
        String jsonString =
                "{" +
                        "   \"vulnerabilities\": [" +
                        "       {" +
                        "           \"cve\": {" +
                        "               \"id\": \"CVE-2023-1234\"," +
                        "               \"published\": \"2023-08-21T12:34:56.789\"," +
                        "               \"vulnStatus\": \"open\"," +
                        "               \"references\":[]" +
                        "           }" +
                        "       }," +
                        "       {" +
                        "           \"cve\": {" +
                        "               \"id\": \"CVE-2023-5678\"," +
                        "               \"published\": \"2023-08-15T08:00:00.123\"," +
                        "               \"vulnStatus\": \"closed\"," +
                        "               \"references\":[]" +
                        "           }" +
                        "       }" +
                        "   ]" +
                        "}";
        when(mockBR.readLine()).thenReturn(jsonString, null);
        nvdCveController.setUrl(mockURL);
        nvdCveController.setDbRepo(mockDbh);

        Set<NvdVulnerability> mockResults = new HashSet<>();

        when(mockDbh.upsertNvdData(anySet())).thenReturn(mockResults);
        when(mockDbh.backfillNvdTimegaps(anySet())).thenReturn(1);

        nvdCveController.updateNvdTables();

        verify(mockDbh).upsertNvdData(anySet());
        verify(mockDbh).backfillNvdTimegaps(anySet());
    }
}