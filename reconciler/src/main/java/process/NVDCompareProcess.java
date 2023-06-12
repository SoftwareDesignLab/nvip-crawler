package process;

import model.CompositeVulnerability;
import nvd.NvdCveController;

import java.util.Set;

public class NVDCompareProcess extends Processor {

    private static final NvdCveController NVD_CONTROLLER = new NvdCveController();

    @Override
    public void process(Set<CompositeVulnerability> vulns) {
        // TODO: gotta add the URL as an envvar
        NVD_CONTROLLER.updateNvdDataTable("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=<StartDate>&pubEndDate=<EndDate>");
        NVD_CONTROLLER.compareReconciledCVEsWithNVD(vulns);
    }
}
