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
package edu.rit.se.nvip.automatedcvss;

import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author axoeec
 *
 */
public class PartialCvssVectorGenerator {

	/**
	 * A partial CVSS vector is a list like ["P", "X", "X", "X", "X", "H", "H",
	 * "H"], where each item in the list represents the values of AV, AC, PR, UI, S,
	 * C, I, A, respectively
	 * 
	 * AV: Attack Vector, AC: Attack Complexity, PR: Privilege Required, S: Scope,
	 * UI: User Interaction, C: Confidentiality, I: Integrity, A: Availability.
	 * 
	 * Note: Right now we do not have any mapping for: PR, UI, S fields of the CVSS
	 * vector
	 * 
	 * @param predictionsForVuln: Predictions for each VDO noun group. The value of
	 *                            the map is ArrayList<String[]> to store the label
	 *                            and confidence for each noun group value.
	 * @return
	 */
	public String[] getCVssVector(Map<VDONounGroup, Map<VDOLabel, Double>> predictionsForVuln) {

		// values for: AV, AC, PR, UI, S, C, I, A
		// initially set to unknown
		String[] vectorCvss = new String[] { "X", "L", "X", "X", "U", "N", "N", "N" };

		Map<VDOLabel, Integer> predictedLabelMap;

		for (VDONounGroup vdoNounGroup : predictionsForVuln.keySet()) {
			Map<VDOLabel, Double> predictionsForNounGroup = predictionsForVuln.get(vdoNounGroup);

			predictedLabelMap = new HashMap<>(); // create map
			// put labels into the map to avoid repeated list iterations
			for (VDOLabel label : predictionsForNounGroup.keySet()) {
				predictedLabelMap.put(label, 0);
			}
			// attack theater
			if (vdoNounGroup == VDONounGroup.ATTACK_THEATER) {
				/**
				 * Attack Vector (AV)* Network (AV:N), Adjacent (AV:A), Local (AV:L), Physical
				 * (AV:P)
				 * 
				 */
				if (predictedLabelMap.containsKey(VDOLabel.REMOTE))
					vectorCvss[0] = "N";
				else if (predictedLabelMap.containsKey(VDOLabel.LIMITED_RMT))
					vectorCvss[0] = "N";
				else if (predictedLabelMap.containsKey(VDOLabel.LOCAL))
					vectorCvss[0] = "L";
				else if (predictedLabelMap.containsKey(VDOLabel.PHYSICAL))
					vectorCvss[0] = "P";

			} else if (vdoNounGroup == VDONounGroup.CONTEXT) {
				// no mapping yet
			} else if (vdoNounGroup == VDONounGroup.IMPACT_METHOD) {
				/**
				 * Attack Complexity (AC)* Low (AC:L)High (AC:H)
				 * 
				 */
				if (predictedLabelMap.containsKey(VDOLabel.MAN_IN_THE_MIDDLE))
					vectorCvss[1] = "H"; // if there is MitM impact then, we assume attack complexity is High
				else if (predictedLabelMap.containsKey(VDOLabel.CONTEXT_ESCAPE))
					vectorCvss[4] = "C"; // scope changes if context escape

			} else if (vdoNounGroup == VDONounGroup.LOGICAL_IMPACT) {

				/**
				 * ******************* CONFIDENTIALITY **************************
				 * 
				 * (Privilege Escalation && (len(Logical Impact)==1 || Read || Indirect
				 * Disclosure)) -> C: H
				 * 
				 * Read || Indirect Disclosure-> C: LH
				 * 
				 * ******************* INTEGRITY **************************
				 * 
				 * (Privilege Escalation && (len(Logical Impact)==1) || Write || Resource
				 * Removal)) -> I: H
				 * 
				 * Write || Resource Removal -> I: LH
				 * 
				 * 
				 * ******************* AVAILABILITY **************************
				 * 
				 * (Privilege Escalation && (len(Logical Impact)==1 || Service Interrupt)) -> A:
				 * H
				 * 
				 * Service Interrupt -> A:LH
				 * 
				 */
				if (predictedLabelMap.containsKey(VDOLabel.PRIVILEGE_ESCALATION)
						&& (predictedLabelMap.size() == 1 || predictedLabelMap.containsKey(VDOLabel.READ) || predictedLabelMap.containsKey(VDOLabel.INDIRECT_DISCLOSURE))

				)
					vectorCvss[5] = "H"; // confidentiality H
				else if (predictedLabelMap.containsKey(VDOLabel.PRIVILEGE_ESCALATION)
						&& (predictedLabelMap.size() == 1 || predictedLabelMap.containsKey(VDOLabel.WRITE) || predictedLabelMap.containsKey(VDOLabel.RESOURCE_REMOVAL))

				)
					vectorCvss[6] = "H"; // integrity H
				else if (predictedLabelMap.containsKey(VDOLabel.PRIVILEGE_ESCALATION) && (predictedLabelMap.size() == 1 || predictedLabelMap.containsKey(VDOLabel.SERVICE_INTERRUPT))

				)
					vectorCvss[7] = "H"; // availability H
				else if (predictedLabelMap.containsKey(VDOLabel.READ) || predictedLabelMap.containsKey(VDOLabel.INDIRECT_DISCLOSURE))
					vectorCvss[5] = "LH"; // confidentiality LH
				else if (predictedLabelMap.containsKey(VDOLabel.WRITE) || predictedLabelMap.containsKey(VDOLabel.RESOURCE_REMOVAL))
					vectorCvss[6] = "LH"; // integrity LH
				else if (predictedLabelMap.containsKey(VDOLabel.SERVICE_INTERRUPT))
					vectorCvss[7] = "LH"; // availability LH

			} else if (vdoNounGroup == VDONounGroup.MITIGATION) {
				if (predictedLabelMap.containsKey(VDOLabel.SANDBOXED))
					vectorCvss[4] = "C"; // we assume a scope change if "sandboxed" is feasible for mitigation

			}

		}
		return vectorCvss;
	}

}
