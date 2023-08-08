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

import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;

/**
 * 
 * @author axoeec
 *
 */
public class VdoCharacteristic {
	private String cveId;
	private final VDOLabel vdoLabel;
	private final double vdoConfidence;
	private final VDONounGroup vdoNounGroup;

	public VdoCharacteristic(String cveId, VDOLabel vdoLabel, double vdoConfidence, VDONounGroup vdoNounGroup) {
		super();
		this.cveId = cveId;
		this.vdoLabel = vdoLabel;
		this.vdoConfidence = vdoConfidence;
		this.vdoNounGroup = vdoNounGroup;
	}

	public String getCveId() {
		return cveId;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public double getVdoConfidence() {
		return vdoConfidence;
	}

	public VDOLabel getVdoLabel() {
		return vdoLabel;
	}

	public VDONounGroup getVdoNounGroup() {
		return vdoNounGroup;
	}

	@Override
	public String toString() {
		return "VdoCharacteristic [cveId=" + cveId + ", vdoLabel=" + vdoLabel + ", vdoConfidence=" + vdoConfidence + "]";
	}

}
