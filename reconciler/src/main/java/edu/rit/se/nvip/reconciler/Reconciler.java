/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.reconciler;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.db.repositories.RawDescriptionRepository;
import edu.rit.se.nvip.db.repositories.VulnerabilityRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.db.model.CompositeVulnerability;
import org.checkerframework.checker.nullness.qual.NonNull;

/**
 * Abstract class for Cve reconciliation and validation
 * 
 * @author Igor Khokhlov
 *
 */
public abstract class Reconciler {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	protected Map<String, Integer> knownCveSources = new HashMap<>();

	protected boolean considerSources;

	enum MergeStrategy {
		UPDATE_ONE_BY_ONE,
		RESYNTH,
		UPDATE_BULK
	}

	public void setKnownCveSources(Map<String, Integer> knownCveSources) {
		this.knownCveSources = knownCveSources;
	}

	/**
	 * Merges information from RawVulnerabilities into a CompositeVulnerability. Date reconciliation is trivially order-based
	 * and happens internally within the CompostiteVulnerability class
	 * @param existingVuln A (possibly null) CompositeVulnerability
	 * @param newVulns A non-null list of RawVulnerabilities with the same CVE-XXX-XXXX identifier as the existingVuln. Filter status will not be checked here, and all rawvulns are assumed to be equal priority
	 * @return A CompositeVulnerability containing merged and updated information
	 */
	public CompositeVulnerability reconcile(CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns) {
		if (newVulns.isEmpty()) {
			return existingVuln;
			// todo handle the case where we have no passed rawvulns and no existingvuln but still want to report something
		}
		// take the user edits out of the newVulns set and apply the most recent one
		List<RawVulnerability> newUserEdits = extractUserSources(newVulns); // sorted by newest created date first
		if (!newUserEdits.isEmpty()) {
			RawVulnerability latestNewUserEdit = newUserEdits.get(0);
			// a user edit should guarantee that existingVuln exists, but just in case...
			if (existingVuln == null) {
				logger.warn("Attempt to reconcile a user edit for a nonexistent CVE {}", latestNewUserEdit.getCveId());
				return null;
			}
			existingVuln.applyUserEdit(latestNewUserEdit);
			// if the only new sources were user sources then they were all removed and the list is empty
			// if there are no additional non-user sources, then short-circuit a return
			if (newVulns.isEmpty()) {
				return existingVuln;
			}
			// if there are also new non-user sources, store a copy of the composite user description and then continue reconciling on top of it
			else {
				new VulnerabilityRepository(DatabaseHelper.getInstance().getDataSource()).insertDescription(existingVuln.getSystemDescription());
			}
		}
		// if the existing vuln only uses low prio sources and the new ones are high prio, we dump the old sources and rebuild
		if (existingVuln != null && !existingVuln.usesHighPrio() && hasHighPrio(newVulns)) {
			existingVuln.resetDescription();
		}
		CompositeVulnerability reconciledVuln = null;
		// TODO figure out what to do if a new rawvulnerability is an updated version of one of the existing sources, right now nothing special happens
		switch (getMergeStrategy(existingVuln, newVulns)) {
			case RESYNTH:
				reconciledVuln = resynthHandler(existingVuln, newVulns);
				break;
			case UPDATE_ONE_BY_ONE:
				reconciledVuln = oneByOneHandler(existingVuln, newVulns);
				break;
			case UPDATE_BULK:
				// existing should never be null in this case, but we'll clean up the extending class's mistake anyway
				if (existingVuln == null) {
					reconciledVuln = resynthHandler(null, newVulns);
				} else {
					reconciledVuln = bulkHandler(existingVuln, newVulns);
				}
				break;
			default:
				break;
		}
		return reconciledVuln;
	}

	private CompositeVulnerability resynthHandler(CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns) {
		Set<RawVulnerability> totalRawList;
		if (existingVuln == null) {
			totalRawList = newVulns;
		} else {
			totalRawList = Stream.concat(existingVuln.getComponents().stream(), newVulns.stream()).collect(Collectors.toSet());
		}
		String reconciledDescription = synthDescriptionFromScratch(totalRawList);
		if (existingVuln == null) {
			return CompositeVulnerability.fromSet(newVulns, reconciledDescription);
		}
		existingVuln.updateSystemDescription(reconciledDescription, newVulns, true);
		return existingVuln;
	}

	private CompositeVulnerability oneByOneHandler(CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns) {
		CompositeVulnerability reconciledVuln = existingVuln;
		Set<RawVulnerability> vulnsToUse = new HashSet<>(newVulns);
		// if nothing already existed then make a compvuln from one of the newvulns and remove it from the set
		if (reconciledVuln == null) {
			Iterator<RawVulnerability> it = vulnsToUse.iterator();
			reconciledVuln = new CompositeVulnerability(it.next());
			it.remove();
		}
		for (RawVulnerability vuln : vulnsToUse) {
			String runningDescription = singleUpdateDescription(reconciledVuln, vuln);
			Set<RawVulnerability> dummySet = new HashSet<>();
			dummySet.add(vuln);
			reconciledVuln.updateSystemDescription(runningDescription, dummySet, false);
		}
		return reconciledVuln;
	}

	private CompositeVulnerability bulkHandler(@NonNull CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns) {
		String bulkUpdatedDescription = bulkUpdateDescription(existingVuln, newVulns);
		existingVuln.updateSystemDescription(bulkUpdatedDescription, newVulns, false);
		return existingVuln;
	}

	protected static boolean hasHighPrio(Set<RawVulnerability> rawVulns) {
		// when the new vulns hit the reconciler we can assume they're equal priority, so just check the first one
		for (RawVulnerability v : rawVulns) {
			return v.isHighPriority();
		}
		return false;
	}

	private List<RawVulnerability> extractUserSources(Set<RawVulnerability> rawVulns) {
		List<RawVulnerability> out = rawVulns.stream()
				.filter(v->v.getSourceType()== RawVulnerability.SourceType.USER)
				.sorted(Comparator.comparing(RawVulnerability::getCreateDate).reversed())
				.collect(Collectors.toList());
		out.forEach(rawVulns::remove);
		return out;
	}

	/**
	 * Given an existing composite vulnerability and a list of new raw vulnerabilities, determine which merging strategy to use.
	 * Let f denote an implementation of a particular merging strategy
	 * UPDATE_ONE_BY_ONE means the outcome is f(f(f(E, n1), n2), n3)
	 * RESYNTH means to split apart the existing into its components and treat them on equal footing with the new sources, so the output is f(e1, e2, e3, n1, n2, n3)
	 * UPDATE_BULK means to regard the merge as an update, but all new vulns should be on equal footing, so the output is f(E, n1, n2, n3). THIS SHOULD NEVER BE RETURNED IF existingVuln IS NULL!!!
	 * What actually happens in the implementation of each case is up to the implementer, but from the abstract perspective the buildstring will reflect the merge strategy
	 * @param existingVuln A (possibly null) existing composite vulnerability
	 * @param newVulns A non-null list of new raw vulnerabilities to merge
	 * @return The merge strategy to follow
	 */
	public abstract MergeStrategy getMergeStrategy(CompositeVulnerability existingVuln, Set<RawVulnerability> newVulns);

	/**
	 * Merge descriptions using the UPDATE_BULK merge, i.e. the outcome is treated f(E, n1, n2, n3, ...)
	 * @param exitingVuln Existing NON-NULL composite vulnerability
	 * @param newVulns list of new raw vulnerabilities
	 * @return reconciled string description
	 */
	public abstract String bulkUpdateDescription(CompositeVulnerability exitingVuln, Set<RawVulnerability> newVulns);

	/**
	 * Merge descriptions using the RESYNTH merge, i.e. the outcome is treated as f(v1, v2, v3, ...)
	 * @param vulns list of rawvulnerbilities to merge
	 * @return reconciled string description
	 */
	public abstract String synthDescriptionFromScratch(Set<RawVulnerability> vulns);

	/**
	 * Merge an existing composite vulnerability with a single new raw vulnerability. Used by the UPDATE_ONE_BY_ONE strategy
	 * @param oldVuln existing composite vulnerabilityh, possibly null
	 * @param newVuln non-null new raw vulnerability
	 * @return reconciled string description
	 */
	public abstract String singleUpdateDescription(CompositeVulnerability oldVuln, RawVulnerability newVuln);
}
