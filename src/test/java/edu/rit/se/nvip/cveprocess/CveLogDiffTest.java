package edu.rit.se.nvip.cveprocess;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.collections4.SetUtils;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.assertTrue;

public class CveLogDiffTest {

    @Test
    public void testLogAnddiffCVEs() {
        MyProperties properties = new MyProperties();
        properties = new PropertyLoader().loadConfigFile(properties);

        CveLogDiff cveLogger = new CveLogDiff(properties);

        HashMap<String, List<Object>> newCVEMap = new HashMap<>();

        Set<Object> allCveData = new HashSet<>();
        Set<Object> newCVEDataNotInMitre = new HashSet<>();
        Set<Object> newCVEDataNotInNvd = new HashSet<>();

        CompositeVulnerability allVuln = new CompositeVulnerability(0, "url", "CVE-1999-0001",
                "none", "2023-01-01", "2023-01-01", "description", "domain");

        CompositeVulnerability notInMitreVuln = new CompositeVulnerability(1, "url", "CVE-1999-0002",
                "none", "2023-01-01", "2023-01-01", "description", "domain");

        CompositeVulnerability notInNvdVuln = new CompositeVulnerability(2, "url", "CVE-1999-0003",
                "none", "2023-01-01", "2023-01-01", "description", "domain");


        allCveData.add(allVuln);
        newCVEDataNotInMitre.add(notInMitreVuln);
        newCVEDataNotInNvd.add(notInNvdVuln);

        newCVEMap.put("all", Arrays.asList(allCveData.toArray())); // all CVEs
        newCVEMap.put("mitre", Arrays.asList(newCVEDataNotInMitre.toArray())); // CVEs not in Mitre
        newCVEMap.put("nvd", Arrays.asList(newCVEDataNotInNvd.toArray())); // CVEs not in Nvd
        newCVEMap.put("nvd-mitre", Arrays.asList(SetUtils.intersection(newCVEDataNotInMitre, newCVEDataNotInNvd).toArray())); // CVEs not in Nvd and Mitre

        cveLogger.logAndDiffCVEs(1000, 2000, newCVEMap, newCVEMap.size());
        assertTrue(true);
    }
}
