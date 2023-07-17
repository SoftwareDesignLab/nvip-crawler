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

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author axoeec
 *
 */
public class DailyRun {
	int runId = 0;
	String runDateTime;
	float crawlTimeMin;
	int totalCveCount;
	int notInNvdCount;
	int notInMitreCount;
	int notInBothCount;
	int newCveCount;
	double avgTimeGapNvd = 0;
	double avgTimeGapMitre = 0;
	double databaseTimeMin;

	int addedCveCount = 0;
	int updatedCveCount = 0;

	public DailyRun(String runDateTime, float crawlTimeMin, int totalCveCount, int notInNvdCount, int notInMitreCount, int notInBothCount) {
		this.runDateTime = runDateTime;
		this.crawlTimeMin = crawlTimeMin;
		this.totalCveCount = totalCveCount;
		this.notInNvdCount = notInNvdCount;
		this.notInMitreCount = notInMitreCount;
		this.notInBothCount = notInBothCount;
	}

	public DailyRun() {}

	public String getRunDateTime() {
		return runDateTime;
	}

	public float getCrawlTimeMin() {
		return crawlTimeMin;
	}

	public int getTotalCveCount() {
		return totalCveCount;
	}

	public int getNotInNvdCount() {
		return notInNvdCount;
	}

	public int getNotInMitreCount() {
		return notInMitreCount;
	}

	public int getNotInBothCount() {
		return notInBothCount;
	}

	public void calculateAddedUpdateCVEs(List<CompositeVulnerability> crawledVulnerabilityList) {
		// Count added/updated CVEs
		int addedCveCount = 0, updatedCveCount = 0;
		for (CompositeVulnerability vuln : crawledVulnerabilityList) {
			if (vuln.getCveReconcileStatus().equals(CompositeVulnerability.CveReconcileStatus.INSERT))
				addedCveCount++;
			else if (vuln.getCveReconcileStatus().equals(CompositeVulnerability.CveReconcileStatus.UPDATE))
				updatedCveCount++;
		}

		this.addedCveCount = addedCveCount;
		this.updatedCveCount = updatedCveCount;
	}

	/**
	 * Old function for calculating average time gaps per run
	 * TODO: Deprecate this and use DBHelper instead for now
	 * @param crawledVulnerabilityList
	 */
	public void calculateAvgTimeGaps(List<CompositeVulnerability> crawledVulnerabilityList) {
		// Add up all time gaps, then get the mean average
		int totalTimeGapNvd = 0;
		int totalTimeGapMitre = 0;
		for (CompositeVulnerability cve: crawledVulnerabilityList) {
			totalTimeGapNvd += cve.getTimeGapNvd();
			totalTimeGapMitre += cve.getTimeGapMitre();
		}

		double avgNvdtimeGap = totalTimeGapNvd / crawledVulnerabilityList.size();
		this.setAvgTimeGapNvd(avgNvdtimeGap);

		double avgMitreTimeGap = totalTimeGapMitre / crawledVulnerabilityList.size();
		this.setAvgTimeGapMitre(avgMitreTimeGap);
	}

	public int getNewCveCount() {
		return newCveCount;
	}

	public void setNewCveCount(int newCveCount) { this.newCveCount = newCveCount; }
	public double getAvgTimeGapNvd() {
		return avgTimeGapNvd;
	}

	public double getAvgTimeGapMitre() {
		return avgTimeGapMitre;
	}

	public void setRunDateTime(String runDateTime) {
		this.runDateTime = runDateTime;
	}

	public void setCrawlTimeMin(float crawlTimeMin) { this.crawlTimeMin = crawlTimeMin;}

	public void setTotalCveCount(int totalCveCount) {
		this.totalCveCount = totalCveCount;
	}

	public void setNotInNvdCount(int notInNvdCount) {
		this.notInNvdCount = notInNvdCount;
	}

	public void setNotInMitreCount(int notInMitreCount) {
		this.notInMitreCount = notInMitreCount;
	}

	public void setNotInBothCount(int notInBothCount) {
		this.notInBothCount = notInBothCount;
	}

	public void setAvgTimeGapNvd(double avgTimeGapNvd) {
		this.avgTimeGapNvd = avgTimeGapNvd;
	}

	public void setAvgTimeGapMitre(double avgTimeGapMitre) {
		this.avgTimeGapMitre = avgTimeGapMitre;
	}

	public double getDatabaseTimeMin() {
		return databaseTimeMin;
	}

	public void setDatabaseTimeMin(double databaseTimeMin) {
		this.databaseTimeMin = databaseTimeMin;
	}

	public int getRunId() {
		return runId;
	}

	public void setRunId(int runId) { this.runId = runId;}

	public int getAddedCveCount() {
		return addedCveCount;
	}

	public void setAddedCveCount(int addedCveCount) {
		this.addedCveCount = addedCveCount;
	}

	public int getUpdatedCveCount() {
		return updatedCveCount;
	}

	public void setUpdatedCveCount(int updatedCveCount) {
		this.updatedCveCount = updatedCveCount;
	}
	
	

}
