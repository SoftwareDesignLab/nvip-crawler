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

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

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
	public String[] getCVssVector(Set<VDOLabel> predictionsForVuln) {

		// values for: AV, AC, PR, UI, S, C, I, A
		// initially set to unknown
		String[] vectorCvss = new String[] { "X", "L", "X", "X", "U", "N", "N", "N" };
		Map<VDONounGroup, Set<VDOLabel>> nounToLabels = predictionsForVuln.stream().collect(Collectors.groupingBy(v->v.vdoNounGroup, Collectors.toSet()));

		for (VDONounGroup vdoNounGroup : nounToLabels.keySet()) {
			Set<VDOLabel> predictionsForNounGroup = nounToLabels.get(vdoNounGroup);
			// attack theater
			if (vdoNounGroup == VDONounGroup.ATTACK_THEATER) {
				/**
				 * Attack Vector (AV)* Network (AV:N), Adjacent (AV:A), Local (AV:L), Physical
				 * (AV:P)
				 * 
				 */
				if (predictionsForNounGroup.contains(VDOLabel.REMOTE))
					vectorCvss[0] = "N";
				else if (predictionsForNounGroup.contains(VDOLabel.LIMITED_RMT))
					vectorCvss[0] = "N";
				else if (predictionsForNounGroup.contains(VDOLabel.LOCAL))
					vectorCvss[0] = "L";
				else if (predictionsForNounGroup.contains(VDOLabel.PHYSICAL))
					vectorCvss[0] = "P";

			} else if (vdoNounGroup == VDONounGroup.CONTEXT) {
				// no mapping yet
			} else if (vdoNounGroup == VDONounGroup.IMPACT_METHOD) {
				/**
				 * Attack Complexity (AC)* Low (AC:L)High (AC:H)
				 * 
				 */
				if (predictionsForNounGroup.contains(VDOLabel.MAN_IN_THE_MIDDLE))
					vectorCvss[1] = "H"; // if there is MitM impact then, we assume attack complexity is High
				else if (predictionsForNounGroup.contains(VDOLabel.CONTEXT_ESCAPE))
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
				if (predictionsForNounGroup.contains(VDOLabel.PRIVILEGE_ESCALATION)
						&& (predictionsForNounGroup.size() == 1 || predictionsForNounGroup.contains(VDOLabel.READ) || predictionsForNounGroup.contains(VDOLabel.INDIRECT_DISCLOSURE))

				)
					vectorCvss[5] = "H"; // confidentiality H
				else if (predictionsForNounGroup.contains(VDOLabel.PRIVILEGE_ESCALATION)
						&& (predictionsForNounGroup.size() == 1 || predictionsForNounGroup.contains(VDOLabel.WRITE) || predictionsForNounGroup.contains(VDOLabel.RESOURCE_REMOVAL))

				)
					vectorCvss[6] = "H"; // integrity H
				else if (predictionsForNounGroup.contains(VDOLabel.PRIVILEGE_ESCALATION) && (predictionsForNounGroup.size() == 1 || predictionsForNounGroup.contains(VDOLabel.SERVICE_INTERRUPT))

				)
					vectorCvss[7] = "H"; // availability H
				else if (predictionsForNounGroup.contains(VDOLabel.READ) || predictionsForNounGroup.contains(VDOLabel.INDIRECT_DISCLOSURE))
					vectorCvss[5] = "LH"; // confidentiality LH
				else if (predictionsForNounGroup.contains(VDOLabel.WRITE) || predictionsForNounGroup.contains(VDOLabel.RESOURCE_REMOVAL))
					vectorCvss[6] = "LH"; // integrity LH
				else if (predictionsForNounGroup.contains(VDOLabel.SERVICE_INTERRUPT))
					vectorCvss[7] = "LH"; // availability LH

			} else if (vdoNounGroup == VDONounGroup.MITIGATION) {
				if (predictionsForNounGroup.contains(VDOLabel.SANDBOXED))
					vectorCvss[4] = "C"; // we assume a scope change if "sandboxed" is feasible for mitigation

			}

		}
		return vectorCvss;
	}

	/**
	 * Brute forces all possible output vectors, stores in a csv.
	 * this is not maintained code.
	 * @param args
	 */
	public static void main(String[] args) {
		Set<VDOLabel> enumSet = new LinkedHashSet<>(Arrays.asList(VDOLabel.values()));
		Set<VDOLabel> currentSubset = new LinkedHashSet<>();
		Set<String> outputs = new LinkedHashSet<>();
		// recursively compute all outputs over the power set of vdolabel
		evaluateSubset(outputs, new PartialCvssVectorGenerator(), enumSet, currentSubset);
		outputs = outputs.stream().map(s->s.substring(0,s.length()-1)).collect(Collectors.toSet()); //remove trailing commas
		System.out.println(outputs.size());
		System.out.println(enumSet.size());
		String outputPath = "nvip_data/cvss/vector_outputs.csv";
		try {
			FileWriter writer = new FileWriter(outputPath);
			for (String output : outputs) {
				writer.append(output);
				writer.append("\n");
			}
			writer.flush();
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		// compare old and new cvss methods
		CvssScoreCalculator calc = new CvssScoreCalculator();
		for (String output : outputs) {
			double old = calc.getCvssScoreJython(output.split(","))[0];
			double imp = calc.lookupCvssScore(output.split(","));
			System.out.printf("%.3f, %.3f\n", old, imp);
			if (old != imp) {
				System.out.println("MISMATCH");
			}
		}
	}
	private static void evaluateSubset(Set<String> outputs, PartialCvssVectorGenerator f, Set<VDOLabel> remainingSet, Set<VDOLabel> currentSubset) {
		if (remainingSet.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			for (String s : f.getCVssVector(currentSubset)) {
				sb.append(s);
				sb.append(",");
			}
			outputs.add(sb.toString());
			return;
		}
		VDOLabel element = remainingSet.iterator().next();
		remainingSet.remove(element);
		evaluateSubset(outputs, f, remainingSet, currentSubset);
		currentSubset.add(element);
		evaluateSubset(outputs, f, remainingSet, currentSubset);
		currentSubset.remove(element);
		remainingSet.add(element);
	}
}
