package edu.rit.se.nvip;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.filter.FilterHandler;
import edu.rit.se.nvip.filter.FilterReturn;
import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.model.RunStats;
import edu.rit.se.nvip.nvd.NvdCveController;
import edu.rit.se.nvip.reconciler.Reconciler;
import edu.rit.se.nvip.reconciler.ReconcilerFactory;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.*;

class ReconcilerControllerTest {

    /**
     * lots of mocks but this  verifies that everything is being called correctly for the reconciler controller
     */
    @Test
    void mainTest() {
        //create mocks
        ReconcilerController rc = new ReconcilerController();
        MockedStatic<ReconcilerEnvVars> mockedEnvVars = mockStatic(ReconcilerEnvVars.class);
        MockedStatic<DatabaseHelper> mockedDb = mockStatic(DatabaseHelper.class);
        DatabaseHelper mockDbh = mock(DatabaseHelper.class);
        FilterHandler mockFH = mock(FilterHandler.class);
        Reconciler mockRecon = mock(Reconciler.class);
        FilterReturn mockFR = mock(FilterReturn.class);
        Messenger mockMes = mock(Messenger.class);
        MitreCveController mockMitre = mock(MitreCveController.class);
        NvdCveController mockNvd = mock(NvdCveController.class);
        CveCharacterizer mockChar = mock(CveCharacterizer.class);
        rc.setDbh(mockDbh);
        rc.setReconciler(mockRecon);
        rc.setFilterChain(mockFH);
        rc.setMessenger(mockMes);
        rc.setNvdController(mockNvd);
        rc.setMitreController(mockMitre);
        rc.setCveCharacterizer(mockChar);

        //create mock functionality
        mockedEnvVars.when(ReconcilerEnvVars::getDoCharacterization).thenReturn(true);
        Set<RawVulnerability> rawVulns = new HashSet<>();
        RawVulnerability raw = new RawVulnerability(1, "", "description1", null, null, null, "");
        RawVulnerability raw1 = new RawVulnerability(2, "", "description2", null, null, null, "");
        RawVulnerability raw2 = new RawVulnerability(3, "", "description3", null, null, null, "");
        rawVulns.add(raw);
        rawVulns.add(raw1);
        rawVulns.add(raw2);
        CompositeVulnerability vuln = new CompositeVulnerability(raw);

        when(mockDbh.getRawVulnerabilities(anyString())).thenReturn(rawVulns);
        when(mockDbh.getCompositeVulnerability(anyString())).thenReturn(vuln);
        when(mockFH.runFilters(anySet())).thenReturn(mockFR);
        doNothing().when(mockDbh).updateFilterStatus(anySet());
        when(mockRecon.reconcile(any(CompositeVulnerability.class), anySet())).thenReturn(vuln);
        when(mockDbh.insertOrUpdateVulnerabilityFull(any(CompositeVulnerability.class))).thenReturn(1);
        doNothing().when(mockMes).sendPNEMessage(anyList());
        when(mockDbh.insertTimeGapsForNewVulns(anySet())).thenReturn(1);
        when(mockDbh.insertRun(any(RunStats.class))).thenReturn(1);
        when(mockDbh.insertCvssBatch(anySet())).thenReturn(1);
        when(mockDbh.insertVdoBatch(anySet())).thenReturn(1);
        doNothing().when(mockMitre).updateMitreTables();
        doNothing().when(mockNvd).updateNvdTables();
        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDbh);


        //actually run the code
        Set<String> jobs = new HashSet<>();
        jobs.add("CVE-2023-1");
        jobs.add("CVE-2023-2");
        jobs.add("CVE-2023-3");
        jobs.add("CVE-2023-4");
        rc.main(jobs);

        mockedEnvVars.close();
        mockedDb.close();
    }

    @Test
    public void initTest(){
        ReconcilerController rc = new ReconcilerController();
        DatabaseHelper mockDb = mock(DatabaseHelper.class);
        Reconciler mockRecon = mock(Reconciler.class);
        MockedStatic<DatabaseHelper> mockedDB = mockStatic(DatabaseHelper.class);
        MockedStatic<ReconcilerFactory> mockedRF = mockStatic(ReconcilerFactory.class);

        mockedDB.when(DatabaseHelper::getInstance).thenReturn(mockDb);
        mockedRF.when(() -> ReconcilerFactory.createReconciler(anyString())).thenReturn(mockRecon);
        doNothing().when(mockRecon).setKnownCveSources(anyMap());

        rc.initialize();
    }
}