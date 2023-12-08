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

package edu.rit.se.nvip.mitre;

import com.google.gson.JsonObject;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.repositories.NvdMitreRepository;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.MitreVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.utils.GitController;
import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class MitreCveControllerTest {

    private final MitreCveController mitreCveController = new MitreCveController();
    @Mock
    NvdMitreRepository mockDbh = mock(NvdMitreRepository.class);
    //verifies update tables works correctly with mocks for database methods
    @Test
    public void updateMitreTables() {
        Set<MitreVulnerability> mockResults = new HashSet<>();
        MitreVulnerability mockVulnerability1 = new MitreVulnerability("CVE-1", "Public");
        MitreVulnerability mockVulnerability2 = new MitreVulnerability("CVE-2", "Public");
        MitreVulnerability mockVulnerability3 = new MitreVulnerability("CVE-3", "Reserved");
        mockResults.add(mockVulnerability1);
        mockResults.add(mockVulnerability2);
        mockResults.add(mockVulnerability3);
        GitController mockGit = mock(GitController.class);
        File mockFile = mock(File.class);
        mitreCveController.setGitController(mockGit);
        mitreCveController.setFile(mockFile);
        String[] strings = new String[2];
        when(mockGit.pullRepo()).thenReturn(true);
        when(mockFile.exists()).thenReturn(true, false);
        when(mockFile.list()).thenReturn(strings);
        List<String> dummyPaths = new ArrayList<>();
        dummyPaths.add("src/test/resources/mitreCveControllerTestJson/");
        mitreCveController.setLocalPaths(dummyPaths);
        
        mitreCveController.setDatabaseHelper(mockDbh);
        when(mockDbh.upsertMitreData(anySet())).thenReturn(mockResults);
        when(mockDbh.backfillMitreTimegaps(anySet())).thenReturn(1);

        mitreCveController.updateMitreTables();

        verify(mockDbh).upsertMitreData(anySet());
        verify(mockDbh).backfillMitreTimegaps(anySet());


    }

    //verifies you can get jsons from a given file, a mock file was made in the resources folder
    @Test
    public void getJSONFilesFromGitFolder() throws IOException {
        ArrayList<JsonObject> list = new ArrayList<>();

        File file = new File("src/test/resources/mitreCveControllerTestJson/");

        mitreCveController.getJSONFilesFromGitFolder(file, list);

        assertEquals(1, list.size());

    }

    //verifies that the compare with mitre method can properly compare mitre vulns based on their status
    @Test
    public void compareWithMitre() {
        mitreCveController.setDatabaseHelper(mockDbh);

        Set<CompositeVulnerability> reconciledVulns = new HashSet<>();
        CompositeVulnerability vuln1 = new CompositeVulnerability(new RawVulnerability(1, "CVE-2021-123455", "Description", null, null, null, ""));
        CompositeVulnerability vuln2 = new CompositeVulnerability(new RawVulnerability(2, "CVE-2021-12234", "Description", null, null, null, ""));
        CompositeVulnerability vuln3 = new CompositeVulnerability(new RawVulnerability(3, "CVE-2021-12134", "Description", null, null, null, ""));
        CompositeVulnerability vuln4 = new CompositeVulnerability(new RawVulnerability(4, "CVE-2021-1", "Description", null, null, null, ""));
        reconciledVulns.add(vuln1);
        reconciledVulns.add(vuln2);
        reconciledVulns.add(vuln3);
        reconciledVulns.add(vuln4);

        MitreVulnerability mitreVuln1 = new MitreVulnerability("CVE-2021-123455", "Public");
        MitreVulnerability mitreVuln2 = new MitreVulnerability("CVE-2021-12234","Not in MITRE");
        MitreVulnerability mitreVuln3 = new MitreVulnerability("CVE-2021-12134","Public");
        MitreVulnerability mitreVuln4 = new MitreVulnerability("CVE-2021-1","Reserved");
        vuln1.setMitreVuln(mitreVuln1);
        vuln2.setMitreVuln(mitreVuln2);
        vuln3.setMitreVuln(mitreVuln3);
        vuln4.setMitreVuln(mitreVuln4);

        when(mockDbh.attachMitreVulns(any())).thenReturn(reconciledVulns);
        when(mockDbh.isMitreTableEmpty()).thenReturn(true);

        mitreCveController.compareWithMitre(reconciledVulns);

        verify(mockDbh).attachMitreVulns(any());

        //Output should be 2 in Mitre 2 not in Mitre 1 Reserved 2 Public
    }

    @Test
    public void initializeTest(){
        mitreCveController.setDatabaseHelper(mockDbh);
        when(mockDbh.isMitreTableEmpty()).thenReturn(false);
        mitreCveController.initializeController();
    }
}