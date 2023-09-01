/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
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

import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
	 * @param existingDesc A (possibly null) CompositeVulnerability
	 * @param newVulns A non-null list of RawVulnerabilities with the same CVE-XXX-XXXX identifier as the existingVuln. Filter status will not be checked here, and all rawvulns are assumed to be equal priority
	 * @return A CompositeVulnerability containing merged and updated information
	 */
	public CompositeDescription reconcile(CompositeDescription existingDesc, Set<RawVulnerability> newVulns) {
		if (newVulns.isEmpty()) {
			return existingDesc;
		}
		// if the existing vuln only uses low prio sources and the new ones are high prio, we dump the old sources and rebuild
		CompositeDescription workingDescription;
		if (existingDesc == null || !existingDesc.usesHighPrio() && hasHighPrio(newVulns)) {
			workingDescription = new CompositeDescription((RawVulnerability) null); // todo proper empty constructor
		}
		else {
			workingDescription = existingDesc; //todo copy?
		}
		CompositeDescription reconciledDesc = null;
		// TODO figure out what to do if a new rawvulnerability is an updated version of one of the existing sources, right now nothing special happens
		switch (getMergeStrategy(workingDescription, newVulns)) {
			case RESYNTH:
				reconciledDesc = resynthHandler(workingDescription, newVulns);
				break;
			case UPDATE_ONE_BY_ONE:
				reconciledDesc = oneByOneHandler(workingDescription, newVulns);
				break;
			case UPDATE_BULK:
				reconciledDesc = bulkHandler(workingDescription, newVulns);
				break;
			default:
				break;
		}
		return reconciledDesc;
	}

	private CompositeDescription resynthHandler(CompositeDescription existingDesc, Set<RawVulnerability> newVulns) {
		Set<RawVulnerability> totalRawList = Stream.concat(existingDesc.getSources().stream(), newVulns.stream()).collect(Collectors.toSet());
		String reconciledDescription = synthDescriptionFromScratch(totalRawList);
		existingDesc.addSourcesAndResynth(reconciledDescription, newVulns);
		return existingDesc;
	}

	private CompositeDescription oneByOneHandler(CompositeDescription existingDesc, Set<RawVulnerability> newVulns) {
		for (RawVulnerability vuln : newVulns) {
			String runningDescription = singleUpdateDescription(existingDesc, vuln);
			Set<RawVulnerability> dummySet = new HashSet<>();
			dummySet.add(vuln);
			existingDesc.addSources(runningDescription, dummySet);
		}
		return existingDesc;
	}

	private CompositeDescription bulkHandler(CompositeDescription existingDesc, Set<RawVulnerability> newVulns) {
		String bulkUpdatedDescription = bulkUpdateDescription(existingDesc, newVulns);
		existingDesc.addSources(bulkUpdatedDescription, newVulns);
		return existingDesc;
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
				.filter(v->v.getSourceType()== SourceType.USER)
				.sorted(Comparator.comparing(Vulnerability::getCreateDate).reversed())
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
	 * @param existingDesc A (possibly null) existing composite vulnerability
	 * @param newVulns A non-null list of new raw vulnerabilities to merge
	 * @return The merge strategy to follow
	 */
	public abstract MergeStrategy getMergeStrategy(CompositeDescription existingDesc, Set<RawVulnerability> newVulns);

	/**
	 * Merge descriptions using the UPDATE_BULK merge, i.e. the outcome is treated f(E, n1, n2, n3, ...)
	 * @param existingDesc Existing NON-NULL composite vulnerability
	 * @param newVulns list of new raw vulnerabilities
	 * @return reconciled string description
	 */
	public abstract String bulkUpdateDescription(CompositeDescription existingDesc, Set<RawVulnerability> newVulns);

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
	public abstract String singleUpdateDescription(CompositeDescription oldVuln, RawVulnerability newVuln);
}
