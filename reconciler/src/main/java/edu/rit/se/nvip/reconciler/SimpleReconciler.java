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

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import java.util.Map;
import java.util.Set;

/**
 * Class for simple Cve reconciliation and validation
 *
 * @author Igor Khokhlov
 *
 */

public class SimpleReconciler extends PairwiseChoosingReconciler {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public SimpleReconciler() {
	}

	/**
	 * Reconcile description. If <existingDescription> should be updated, returns
	 * true.
	 *
	 * @param existingDescription
	 * @param newDescription
	 * @return updateDescription
	 */
	@Override
	public boolean reconcileDescriptions(String existingDescription, String newDescription, Set<String> existingSourceDomains, String newSourceDomain) {
		boolean updateDescription = false;

		/**
		 * if existing CVE is from known source (and the new one is not) use existing
		 * description, no need for reconciliation. If existing source is unknown but
		 * the new one is known, update existing description. If both sources are known
		 * then move forward with reconciliation process
		 */
		boolean existingSourceKnown = false;
		for (String source : existingSourceDomains) {
			if (knownCveSources.containsKey(source)) {
				existingSourceKnown = true;
				break;
			}
		}
		if (considerSources && existingSourceKnown && !knownCveSources.containsKey(newSourceDomain))
			return false;

		if (considerSources && !existingSourceKnown && knownCveSources.containsKey(newSourceDomain))
			return true;

		// both CVEs from unknown sources
		if (existingDescription == null || existingDescription.length() < newDescription.length()) {
			updateDescription = true;
			return updateDescription;
		} else {
			return updateDescription;
		}
	}
	public void setKnownCveSources(Map<String, Integer> map){
		knownCveSources = map;
	}
}
