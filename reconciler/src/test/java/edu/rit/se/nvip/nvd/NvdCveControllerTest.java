package edu.rit.se.nvip.nvd;

import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.MitreVulnerability;
import edu.rit.se.nvip.model.NvdVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.sql.Timestamp;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class NvdCveControllerTest {

    private final NvdCveController nvdCveController = new NvdCveController();
    @Mock
    DatabaseHelper mockDbh = mock(DatabaseHelper.class);
    @Test
    void compareWithNvd() {
        nvdCveController.setDatabaseHelper(mockDbh);

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

        NvdVulnerability nvdVuln1 = new NvdVulnerability("CVE-2021-123455", new Timestamp(System.currentTimeMillis()), "Analyzed");
        NvdVulnerability nvdVuln2 = new NvdVulnerability("CVE-2021-12234", new Timestamp(System.currentTimeMillis()), "Received");
        NvdVulnerability nvdVuln3 = new NvdVulnerability("CVE-2021-12134", new Timestamp(System.currentTimeMillis()), "Undergoing Analysis");
        NvdVulnerability nvdVuln4 = new NvdVulnerability("CVE-2021-1", new Timestamp(System.currentTimeMillis()), "Awaiting Analysis");
        NvdVulnerability nvdVuln5 = new NvdVulnerability("CVE-2021-12", new Timestamp(System.currentTimeMillis()), "Not in NVD");
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

    @Test
    void updateNvdTables() {
        nvdCveController.setDatabaseHelper(mockDbh);

        Set<NvdVulnerability> mockResults = new HashSet<>();

        when(mockDbh.upsertNvdData(anySet())).thenReturn(mockResults);
        when(mockDbh.backfillNvdTimegaps(anySet())).thenReturn(1);

        nvdCveController.updateNvdTables(false);

        verify(mockDbh).upsertNvdData(anySet());
        verify(mockDbh).backfillNvdTimegaps(anySet());
    }
}