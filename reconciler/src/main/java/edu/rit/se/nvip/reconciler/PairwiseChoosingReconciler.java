/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package edu.rit.se.nvip.reconciler;

import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;

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
