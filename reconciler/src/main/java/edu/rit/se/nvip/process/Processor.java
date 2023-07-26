package edu.rit.se.nvip.process;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.Set;

/**
 * abstract representation of a processing stage
 */
public abstract class Processor {
    /**
     * Apply "processing" operations to each vulnerability without changing the list contents
     * @param vulns list of vulnerabilities to process
     */
    public abstract void process(Set<CompositeVulnerability> vulns);
}
