package edu.rit.se.nvip.cveprocess;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;


public class CveProcessorTest {

    private final String CVE_ID = "CVE-1999-0001";

    private CveProcessor cveProcessor = new CveProcessor(new HashMap<>(), new HashMap<>());
    private Map<String, CompositeVulnerability> foundVulnerabilities = new HashMap<>();

    @BeforeEach public void addFoundVulnerability(){
        foundVulnerabilities.put(CVE_ID, new CompositeVulnerability(0, CVE_ID));
    }

    @AfterEach void clearFoundVulnerability(){
        foundVulnerabilities.clear();
    }

    @Test
    public void vulnerabilityNotInMitreWhenNoMitreCves(){

        Map<String, Vulnerability> existingCves = new HashMap<>();

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityNotInNvdWhenNoNvdCves(){
        Map<String, Vulnerability> existingCves = new HashMap<>();
        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInNvdWhenIdMatches(){
        HashMap<String, String> cves = new HashMap<>();
        cves.put(CVE_ID, "");
        Map<String, Vulnerability> existingCves = new HashMap<>();
        cveProcessor = new CveProcessor(cves, new HashMap<>());

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInMitreWhenIdMatches(){
        HashMap cves = new HashMap<>();
        cves.put(CVE_ID, "");
        Map<String, Vulnerability> existingCves = new HashMap<>();
        cveProcessor = new CveProcessor(new HashMap<>(), cves);

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInBothWhenIdMatches(){
        HashMap<String, String> cves = new HashMap<>();
        cves.put(CVE_ID, "");
        Map<String, Vulnerability> existingCves = new HashMap<>();
        cveProcessor = new CveProcessor(cves, cves);

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInBothWhenFoundNewDescriptionForReserved() {
        foundVulnerabilities.get(CVE_ID).setFoundNewDescriptionForReservedCve(true);

        HashMap<String, String> cves = new HashMap<>();
        cves.put(CVE_ID, "");
        Map<String, Vulnerability> existingCves = new HashMap<>();
        cveProcessor = new CveProcessor(cves, cves);

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotNvd() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 1, null));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotMitre() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 1, 0, null));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotEither() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 0, null));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotNvdPastMonth() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 0, null));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotMitrePastMonth() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 0,
                "2023-03-26 00:00:00"));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotEitherPastMonth() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 0,
                "2023-03-26 00:00:00"));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }
}
