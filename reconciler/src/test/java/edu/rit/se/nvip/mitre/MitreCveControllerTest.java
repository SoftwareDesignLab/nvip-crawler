package edu.rit.se.nvip.mitre;

import com.google.gson.JsonObject;
import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.MitreVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.GitController;
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;


public class MitreCveControllerTest {

    private final MitreCveController mitreCveController = new MitreCveController();
    @Mock
    DatabaseHelper mockDbh = mock(DatabaseHelper.class);
    @Test
    public void updateMitreTables() {
        Set<MitreVulnerability> mockResults = new HashSet<>();
        MitreVulnerability mockVulnerability1 = new MitreVulnerability("CVE-1", "Public");
        MitreVulnerability mockVulnerability2 = new MitreVulnerability("CVE-2", "Public");
        MitreVulnerability mockVulnerability3 = new MitreVulnerability("CVE-3", "Reserved");
        mockResults.add(mockVulnerability1);
        mockResults.add(mockVulnerability2);
        mockResults.add(mockVulnerability3);

        
        mitreCveController.setDatabaseHelper(mockDbh);
        when(mockDbh.upsertMitreData(anySet())).thenReturn(mockResults);
        when(mockDbh.backfillMitreTimegaps(anySet())).thenReturn(1);

        mitreCveController.updateMitreTables(false);

        verify(mockDbh).upsertMitreData(anySet());
        verify(mockDbh).backfillMitreTimegaps(anySet());


    }

    @Test
    public void getJSONFilesFromGitFolder() throws IOException {
        ArrayList<JsonObject> list = new ArrayList<>();

        File file = new File("src/test/resources/mitreCveControllerTestJson/");

        mitreCveController.getJSONFilesFromGitFolder(file, list);

        assertEquals(1, list.size());

    }
    @Test
    public void getMitreCVEsFromGitRepoTest(){
        GitController mockGit = mock(GitController.class);
        File mockFile = mock(File.class);
        mitreCveController.setGitController(mockGit);
        mitreCveController.setFile(mockFile);
        String[] strings = new String[2];
        when(mockGit.pullRepo()).thenReturn(true);
        when(mockFile.exists()).thenReturn(true, false);
        when(mockFile.list()).thenReturn(strings);

        mitreCveController.getMitreCVEsFromGitRepo(false);
        mitreCveController.getMitreCVEsFromGitRepo(false);

    }

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
}