package edu.rit.se.nvip.process;

import edu.rit.se.nvip.mitre.MitreCveController;
import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.*;
import java.util.stream.Collectors;

public class MITRECompareProcess extends Processor{

    public void process(Set<CompositeVulnerability> vulns){
        MitreCveController controller = new MitreCveController(); // todo use right args, envvars?
        controller.updateMitreTables(); // should pull new mitre data, do inserts/updates for the mitredata table, then do updates for the nvdmitrestatus table
        controller.compareReconciledCVEsWithMitre(vulns);
    }
}
