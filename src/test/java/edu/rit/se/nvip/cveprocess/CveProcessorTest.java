package edu.rit.se.nvip.cveprocess;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.MitreVulnerability;
import edu.rit.se.nvip.model.NvdVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;


public class CveProcessorTest {

    private final String CVE_ID = "CVE-2023-4444";

    private CveProcessor cveProcessor;
    private Map<String, CompositeVulnerability> foundVulnerabilities = new HashMap<>();

    private HashMap<String, NvdVulnerability> testNvdVulns = new HashMap<>();
    private HashMap<String, MitreVulnerability> testMitreVulns = new HashMap<>();




    @BeforeEach public void addFoundVulnerability(){
        testNvdVulns.put(CVE_ID, new NvdVulnerability(CVE_ID, "2023-04-27T00:00:00.000", "2023-04-27T00:00:00.000", "Analyzed"));
        testMitreVulns.put(CVE_ID, new MitreVulnerability(CVE_ID, "2023-04-27T00:00:00.000", "2023-04-27T00:00:00.000", "PUBLIC"));
        cveProcessor = new CveProcessor(new HashMap<>(), new HashMap<>(), testNvdVulns, testMitreVulns);
        foundVulnerabilities.put(CVE_ID, new CompositeVulnerability(0, CVE_ID));
        foundVulnerabilities.get(CVE_ID).setCreateDate("2023-04-26 00:00:00");
    }

    @AfterEach void clearFoundVulnerability(){
        testNvdVulns.clear();
        foundVulnerabilities.clear();
    }

    @Test
    public void vulnerabilityNotInMitreWhenNoMitreCves(){

        Map<String, Vulnerability> existingCves = new HashMap<>();
        testNvdVulns.clear();
        testMitreVulns.clear();
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
        testNvdVulns.clear();
        testMitreVulns.clear();
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
        cveProcessor = new CveProcessor(cves, new HashMap<>(), testNvdVulns, new HashMap<>());

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
        cveProcessor = new CveProcessor(new HashMap<>(), cves, new HashMap<>(), testMitreVulns);

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
        cveProcessor = new CveProcessor(cves, cves, testNvdVulns, testMitreVulns);

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
        cveProcessor = new CveProcessor(cves, cves, testNvdVulns, testMitreVulns);

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

        testNvdVulns.replace(CVE_ID, new NvdVulnerability(CVE_ID, "", "", "notinnvd"));

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
        testMitreVulns.clear();
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
        testNvdVulns.clear();
        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotNvdPastMonth() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 0, null));
        testNvdVulns.clear();
        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityExistsInNvipButNotMitrePastMonth() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 0,
                "2023-03-26 00:00:00"));

        HashMap<String, NvdVulnerability> testNvdVulns = new HashMap<>();
        testNvdVulns.put(CVE_ID, new NvdVulnerability(CVE_ID, "", "","Analyzed"));


        cveProcessor = new CveProcessor(new HashMap<>(), new HashMap<>(), testNvdVulns, testMitreVulns);

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


    @Test
    public void testNewPositiveTimeGap() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 1, "2023-04-26 00:00:00"));

        HashMap<String, String> nvdCve = new HashMap<>();
        nvdCve.put(CVE_ID, "");

        cveProcessor = new CveProcessor(nvdCve, new HashMap<>(), testNvdVulns, testMitreVulns);

        HashMap<String, List<Object>> preProcessedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);
        HashMap<String, List<Object>> withTimeGaps = cveProcessor.checkTimeGaps(preProcessedCves, existingCves);

        assertEquals(0, withTimeGaps.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, withTimeGaps.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, withTimeGaps.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, withTimeGaps.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
        assertEquals(24, foundVulnerabilities.get(CVE_ID).getTimeGapNvd());
    }

    @Test
    public void testNegativeTimeGap() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 1, "2023-04-27 00:00:00"));

        HashMap<String, String> nvdCve = new HashMap<>();
        nvdCve.put(CVE_ID, "");

        cveProcessor = new CveProcessor(nvdCve, new HashMap<>(), testNvdVulns, testMitreVulns);

        HashMap<String, List<Object>> preProcessedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);
        HashMap<String, List<Object>> withTimeGaps = cveProcessor.checkTimeGaps(preProcessedCves, existingCves);

        assertEquals(0, withTimeGaps.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, withTimeGaps.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, withTimeGaps.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, withTimeGaps.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getTimeGapNvd());
    }

    @Test
    public void testPreExistingTimeGap() {
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 1, "2023-04-26 00:00:00"));

        existingCves.get(CVE_ID).setTimeGapNvd(24);

        HashMap<String, String> nvdCve = new HashMap<>();
        nvdCve.put(CVE_ID, "");

        cveProcessor = new CveProcessor(nvdCve, new HashMap<>(), testNvdVulns, testMitreVulns);

        HashMap<String, List<Object>> preProcessedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);
        HashMap<String, List<Object>> withTimeGaps = cveProcessor.checkTimeGaps(preProcessedCves, existingCves);

        assertEquals(0, withTimeGaps.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, withTimeGaps.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, withTimeGaps.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, withTimeGaps.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
        assertEquals(24, foundVulnerabilities.get(CVE_ID).getTimeGapNvd());
    }


    @Test
    public void testBadCVEID() {
        foundVulnerabilities.get(CVE_ID).setCveId("Bad-CVE-ID");
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 1, "2023-04-25 00:00:00"));

        cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);
        assertEquals("Wrong CVE ID! Check for typo?", foundVulnerabilities.get(CVE_ID).getNvipNote());
    }


    @Test
    public void testNotAnalyzedInNVD() {
        testNvdVulns.clear();
        testNvdVulns.put(CVE_ID, new NvdVulnerability(CVE_ID, "", "","Awaiting Analysis"));
        Map<String, Vulnerability> existingCves = new HashMap<>();
        existingCves.put(CVE_ID, new Vulnerability(0, CVE_ID, "", 0, 1, "2023-04-25 00:00:00"));

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities, existingCves);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }


    @Test
    public void testCveIdForYearCheck() {
        assertFalse(cveProcessor.checkAgeOfCVEByYear("CVEID"));
        assertFalse(cveProcessor.checkAgeOfCVEByYear("CVE-2022-0001"));
    }

}
