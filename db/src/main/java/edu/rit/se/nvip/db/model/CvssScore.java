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
package edu.rit.se.nvip.db.model;

import edu.rit.se.nvip.db.model.enums.CVSSSeverityClass;
import lombok.Data;

/**
 * 
 * @author axoeec
 *
 */
@Data
public class CvssScore {
	private String cveId;
	private final CVSSSeverityClass severityClass;
	private final double baseScore;
	private final double confidence;

	public CvssScore(String cveId, double baseScore, double confidence) {
		super();
		this.cveId = cveId;
		this.severityClass = CVSSSeverityClass.getCVSSSeverityByScore(baseScore);
		this.baseScore = baseScore;
		this.confidence = confidence;
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

	public double getBaseScore() {
		return baseScore;
	}

	public double getConfidence() {
		return confidence;
	}

	@Override
	public String toString() {
		return "CvssScore [cveId=" + cveId + ", baseSeverity=" + severityClass + ", baseScore=" + baseScore + ", confidence=" + confidence + "]";
	}
}
