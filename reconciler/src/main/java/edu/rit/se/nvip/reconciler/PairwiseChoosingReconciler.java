package edu.rit.se.nvip.reconciler;

import edu.rit.se.nvip.model.CompositeDescription;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Intermediate abstract reconciler guaranteeing the UPDATE_ONE_BY_ONE strategy and implementing all other strategies by breaking down into pairwise decisions.
 * Requires a mechanism for choosing between two descriptions.
 * All legacy reconcilers follow this pattern and now inherit from this class.
 */
public abstract class PairwiseChoosingReconciler extends Reconciler {

    @Override
    public MergeStrategy getMergeStrategy(CompositeDescription existingDesc, Set<RawVulnerability> newVulns) {
        return MergeStrategy.UPDATE_ONE_BY_ONE;
    }

    @Override
    public String singleUpdateDescription(CompositeDescription oldDesc, RawVulnerability newVuln) {
        if (oldDesc == null) {
            return newVuln.getDescription();
        }
        if (reconcileDescriptions(oldDesc.getDescription(), newVuln.getDescription(), oldDesc.getSourceUrls(), newVuln.getSourceUrl())) {
            return newVuln.getDescription();
        }
        return oldDesc.getDescription();
    }

    @Override
    public String synthDescriptionFromScratch(Set<RawVulnerability> vulns) {
        return bulkUpdateDescription(null, vulns);
    }

    @Override
    public String bulkUpdateDescription(CompositeDescription existingDesc, Set<RawVulnerability> vulns) {
        String runningDescription;
        Set<String> usedSources = new HashSet<>();
        if (existingDesc == null) {
            runningDescription = null;
        }
        else {
            runningDescription = existingDesc.getDescription();
            usedSources.addAll(existingDesc.getSourceUrls());
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
