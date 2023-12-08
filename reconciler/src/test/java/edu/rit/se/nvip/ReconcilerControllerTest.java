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

package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.db.model.RunStats;
import edu.rit.se.nvip.db.repositories.*;
import edu.rit.se.nvip.reconciler.filter.FilterHandler;
import edu.rit.se.nvip.reconciler.filter.FilterReturn;
import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReconcilerControllerTest {

    MockedStatic<DatabaseHelper> mockedDb;
    MockedStatic<ReconcilerEnvVars> mockedEnvVars;

    @BeforeEach
    void initMocks(){
        mockedDb = mockStatic(DatabaseHelper.class);
        mockedEnvVars = mockStatic(ReconcilerEnvVars.class);
    }

    @AfterEach
    void clearMocks(){
        mockedDb.close();
        mockedEnvVars.close();
    }

    /**
     * lots of mocks but this  verifies that everything is being called correctly for the reconciler controller
     */
    @Test
    void mainTest() {
        Set<RawVulnerability> rawVulns = new HashSet<>();
        RawVulnerability raw = new RawVulnerability(1, "", "description1", null, null, null, "");
        RawVulnerability raw1 = new RawVulnerability(2, "", "description2", null, null, null, "");
        RawVulnerability raw2 = new RawVulnerability(3, "", "description3", null, null, null, "");
        rawVulns.add(raw);
        rawVulns.add(raw1);
        rawVulns.add(raw2);

        CompositeVulnerability vuln = new CompositeVulnerability(raw);

        //create mocks
        RawDescriptionRepository mockRawRepo = mock(RawDescriptionRepository.class);
        VulnerabilityRepository mockVulnRepo = mock(VulnerabilityRepository.class);
        CharacterizationRepository mockCharRepo = mock(CharacterizationRepository.class);
        NvdMitreRepository mockNmRepo = mock(NvdMitreRepository.class);
        RunHistoryRepository mockRhRepo = mock(RunHistoryRepository.class);
        when(mockRawRepo.getRawVulnerabilities(anyString())).thenReturn(rawVulns);
        when(mockVulnRepo.getCompositeVulnerability(anyString())).thenReturn(vuln);
        doNothing().when(mockRawRepo).updateFilterStatus(anySet());
        when(mockVulnRepo.insertOrUpdateVulnerabilityFull(any(CompositeVulnerability.class), anyBoolean())).thenReturn(1);
        when(mockNmRepo.insertTimeGapsForNewVulns(anySet())).thenReturn(1);
        when(mockRhRepo.insertRun(any(RunStats.class))).thenReturn(1);
        when(mockCharRepo.insertVdoCvssBatch(anySet())).thenReturn(1);

        FilterHandler mockFH = mock(FilterHandler.class);
        when(mockFH.runFilters(anySet())).thenReturn(mock(FilterReturn.class));

        Reconciler mockRecon = mock(Reconciler.class);
        when(mockRecon.reconcile(any(CompositeVulnerability.class), anySet())).thenReturn(vuln);

        MitreCveController mockMitre = mock(MitreCveController.class);
        doNothing().when(mockMitre).updateMitreTables();

        NvdCveController mockNvd = mock(NvdCveController.class);
        doNothing().when(mockNvd).updateNvdTables();

        CveCharacterizer mockChar = mock(CveCharacterizer.class);

        ReconcilerController rc = new ReconcilerController(mockRawRepo, mockVulnRepo, mockCharRepo, mockNmRepo, mockRhRepo, mockFH, mockRecon, mockNvd, mockMitre);
        rc.setCveCharacterizer(mockChar);

        //create mock functionality
        mockedEnvVars.when(ReconcilerEnvVars::getDoCharacterization).thenReturn(true);

        //actually run the code
        Set<String> jobs = new HashSet<>();
        jobs.add("CVE-2023-1");
        jobs.add("CVE-2023-2");
        jobs.add("CVE-2023-3");
        jobs.add("CVE-2023-4");

        Set<CompositeVulnerability> reconciledVulns = rc.reconcileCves(jobs);
        rc.characterizeCves(reconciledVulns);
        rc.updateTimeGaps(reconciledVulns);
        rc.createRunStats(reconciledVulns);
    }

//    @Test
//    public void initTest(){
//        ReconcilerController rc = new ReconcilerController();
//        DatabaseHelper mockDb = mock(DatabaseHelper.class);
//        Reconciler mockRecon = mock(Reconciler.class);
////        MockedStatic<ReconcilerFactory> mockedRF = mockStatic(ReconcilerFactory.class);
//
//        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
//        mockedEnvVars.when(ReconcilerEnvVars::getReconcilerType).thenReturn("");
////        mockedRF.when(() -> ReconcilerFactory.createReconciler(anyString())).thenReturn(mockRecon);
////        doNothing().when(mockRecon).setKnownCveSources(anyMap());
//
//        rc.initialize();
//    }
}