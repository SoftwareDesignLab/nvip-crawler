package edu.rit.se.nvip.process;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.nvd.NvdCveController;

import java.util.Set;

public class NVDCompareProcess extends Processor {

    private static final NvdCveController NVD_CONTROLLER = new NvdCveController();

    @Override
    public void process(Set<CompositeVulnerability> vulns) {

        NVD_CONTROLLER.compareReconciledCVEsWithNVD(vulns);

        return;
    }
}
