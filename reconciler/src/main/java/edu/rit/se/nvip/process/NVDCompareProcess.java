package edu.rit.se.nvip.process;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.nvd.NvdCveController;

import java.util.Set;

public class NVDCompareProcess extends Processor {

    private static final NvdCveController NVD_CONTROLLER = new NvdCveController();

    @Override
    public void process(Set<CompositeVulnerability> vulns) {
        // TODO: gotta add the URL as an envvar
        NVD_CONTROLLER.updateNvdDataTables("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>");
        NVD_CONTROLLER.compareReconciledCVEsWithNVD(vulns);
    }
}
