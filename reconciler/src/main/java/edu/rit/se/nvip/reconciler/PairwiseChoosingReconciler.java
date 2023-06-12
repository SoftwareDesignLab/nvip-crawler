package reconciler;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;

import java.util.HashSet;
import java.util.Set;

/**
 * Intermediate abstract reconciler guaranteeing the UPDATE_ONE_BY_ONE strategy and implementing all other strategies by breaking down into pairwise decisions.
 * Requires a mechanism for choosing between two descriptions.
 * All legacy reconcilers follow this pattern and now inherit from this class.
 */
public abstract class PairwiseChoosingReconciler extends Reconciler {

    @Override
    public MergeStrategy getMergeStrategy(CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns) {
        return MergeStrategy.UPDATE_ONE_BY_ONE;
    }

    @Override
    public String singleUpdateDescription(CompositeVulnerability oldVuln, RawVulnerability newVuln) {
        if (oldVuln == null) {
            return newVuln.getDescription();
        }
        if (reconcileDescriptions(oldVuln.getDescription(), newVuln.getDescription(), oldVuln.getSources(), newVuln.getSourceUrl())) {
            return newVuln.getDescription();
        }
        return oldVuln.getDescription();
    }

    @Override
    public String synthDescriptionFromScratch(Set<RawVulnerability> vulns) {
        return bulkUpdateDescription(null, vulns);
    }

    @Override
    public String bulkUpdateDescription(CompositeVulnerability existingVuln, Set<RawVulnerability> vulns) {
        String runningDescription;
        Set<String> usedSources = new HashSet<>();
        if (existingVuln == null) {
            runningDescription = null;
        }
        else {
            runningDescription = existingVuln.getDescription();
            usedSources.addAll(existingVuln.getSources());
        }
        for (RawVulnerability raw : vulns) {
            usedSources.add(raw.getSourceUrl());
            if (reconcileDescriptions(runningDescription, raw.getDescription(), usedSources, raw.getSourceUrl())) {
                runningDescription = raw.getDescription();
            }
        }
        return runningDescription;
    }


    public abstract boolean reconcileDescriptions(String existingDescription, String newDescription, Set<String> existingSourceDomains, String newSourceDomain);
}
