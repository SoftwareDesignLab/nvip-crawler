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
package edu.rit.se.nvip.model;

import edu.rit.se.nvip.characterizer.enums.CVSSSeverityClass;

/**
 * 
 * @author axoeec
 *
 */
public class CvssScore {
	private String cveId;
	private final CVSSSeverityClass severityClass;
	private final double severityConfidence;

	private final double impactScore;
	private final double impactConfidence;

	public CvssScore(String cveId, CVSSSeverityClass severityClass, double severityConfidence, double impactScore, double impactConfidence) {
		super();
		this.cveId = cveId;
		this.severityClass = severityClass;
		this.severityConfidence = severityConfidence;
		this.impactScore = impactScore;
		this.impactConfidence = impactConfidence;
	}

	public String getCveId() {
		return cveId;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public CVSSSeverityClass getSeverityClass() {
		return severityClass;
	}

	public double getSeverityConfidence() {
		return severityConfidence;
	}

	public double getImpactScore() {
		return impactScore;
	}

	public double getImpactConfidence() {
		return impactConfidence;
	}

	@Override
	public String toString() {
		return "CvssScore [cveId=" + cveId + ", baseSeverity=" + severityClass + ", severityConfidence=" + severityConfidence + ", impactScore=" + impactScore + ", impactConfidence=" + impactConfidence + "]";
	}

}
