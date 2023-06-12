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
package reconciler;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import edu.rit.se.nvip.reconciler.models.ApacheOpenNLPModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * Class for Cve reconciliation and validation based on Apache Open NLP library
 * 
 * @author Igor Khokhlov
 *
 */

public class ApacheOpenNLPReconciler extends PairwiseChoosingReconciler {

	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	// Identifier of an unidentified language part
	final String unknwnPrt = "``";
	ApacheOpenNLPModel model = null;

	public ApacheOpenNLPReconciler() {
		super();
	}

	public void attachModel(ApacheOpenNLPModel model) {
		this.model = model;
		model.initialize();
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

		if (existingDescription == null) {
			if (newDescription == null) {
				return updateDescription;
			} else {
				updateDescription = true;
				return updateDescription;
			}
		} else {
			if (newDescription == null) {
				return updateDescription;
			}
		}

		// Compare two descriptions ignoring white spaces and letter cases
		if (newDescription.replaceAll("\\s+", "").equalsIgnoreCase(existingDescription.replaceAll("\\s+", ""))) {
			return updateDescription;
		}

		/* Metrics which are used for the reconciliation decision */
		boolean newHasMoreSent, newMoreDiverse, lessUnknwn;

		/* Counters of unidentified language parts in each description */
		int existingUnknw = 0;
		int newUnknw = 0;

		/* Check if new description has more characters */

		String[] existingSentences;
		String[] newSentences;

		existingSentences = detectSentences(existingDescription);
		newSentences = detectSentences(newDescription);

		if (existingSentences == null) {
			existingSentences = new String[] { existingDescription };
		}
		if (newSentences == null) {
			newSentences = new String[] { newDescription };
		}

		/* Check if new description has more sentences */
		newHasMoreSent = newSentences.length >= existingSentences.length;

		/* Calculate diversity of language parts in each description */
		Map<String, Integer> existingDiversity = docLangParts(existingSentences);
		Map<String, Integer> newDiversity = docLangParts(newSentences);

		/* Check if new description has more diverse language parts */
		newMoreDiverse = newDiversity.size() > existingDiversity.size();

		/* Calculate how many unidentified language parts in existing description */
		if (existingDiversity.get(unknwnPrt) != null) {
			existingUnknw = existingDiversity.get(unknwnPrt);
		}

		/* Calculate how many unidentified language parts in new description */
		if (newDiversity.get(unknwnPrt) != null) {
			newUnknw = newDiversity.get(unknwnPrt);
		}

		/* Check if new description has less unidentified language parts */
		lessUnknwn = newUnknw < existingUnknw;
		/*
		 * Decision table
		 * 
		 * lessUnknwn | newLonger | newHasMoreSent | newMoreDiverse | UPDATE 0 | 0 | 0 |
		 * 0 | 0 0 | 0 | 0 | 1 | 0 0 | 0 | 1 | 0 | 0 0 | 0 | 1 | 1 | 1 0 | 1 | 0 | 0 | 0
		 * 0 | 1 | 0 | 1 | 0 0 | 1 | 1 | 0 | 0 0 | 1 | 1 | 1 | 0 1 | 0 | 0 | 0 | 0 1 | 0
		 * | 0 | 1 | 1 1 | 0 | 1 | 0 | 1 1 | 0 | 1 | 1 | 1 1 | 1 | 0 | 0 | 0 1 | 1 | 0 |
		 * 1 | 1 1 | 1 | 1 | 0 | 1 1 | 1 | 1 | 1 | 1
		 */

		/*
		 * Decision table - compressed version lessUnknwn | newLonger | newHasMoreSent |
		 * newMoreDiverse | UPDATE 0 | 0 | 1 | 1 | 1 1 | 0 | 0 | 1 | 1 1 | 0 | 1 | 0 | 1
		 * 1 | 0 | 1 | 1 | 1 1 | 1 | 0 | 1 | 1 1 | 1 | 1 | 0 | 1 1 | 1 | 1 | 1 | 1
		 */

		/* Decision rules implementation based on the decision table (above) */
		if (newHasMoreSent && newMoreDiverse) {
			updateDescription = true;
		} else if (newMoreDiverse && lessUnknwn) {
			updateDescription = true;
		} else if (lessUnknwn && newHasMoreSent) {
			updateDescription = true;
		}

		return updateDescription;
	}

	/**
	 * Calculate diversity of the language parts in a description. Returns a Map
	 * with language parts as a KEY and the number of this laguage part as a VALUE
	 * (counts of how many times this language part occurs in the description).
	 * 
	 * @param sentences
	 * @return diversity object in a form of a Map object
	 */
	private Map<String, Integer> docLangParts(String[] sentences) {
		Map<String, Integer> counts = new HashMap<>();

		for (String sent : sentences) {
			String[] whitespaceTokenizerLine = WhitespaceTokenizer.INSTANCE.tokenize(sent);
			String[] tags = model.tag(whitespaceTokenizerLine);
			for (String part : tags) {
				if (counts.containsKey(part)) {
					counts.put(part, counts.get(part) + 1);
				} else {
					counts.put(part, 1);
				}
			}
		}
		return counts;
	}

	private String[] detectSentences(String paragraph) {
		return model.sentDetect(paragraph);
	}

}
