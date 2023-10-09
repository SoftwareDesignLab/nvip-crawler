package edu.rit.se.nvip.db.model;

import edu.rit.se.nvip.db.model.CvssScore;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for CvssScore Model
 */
public class CvssScoreTest {
    @Test
    public void testCvssScore() {
        CvssScore obj = new CvssScore("cve_id", 0, 1, "impact_score", 2);

        assertEquals(obj.getCveId(), "cve_id");
        assertEquals(obj.getSeverityId(), 0);
        assertEquals(obj.getSeverityConfidence(), 1, 0.1);
        assertEquals(obj.getImpactScore(), "impact_score");
        assertEquals(obj.getImpactConfidence(), 2, 0.1);

        obj.setCveId("new_cve_id");

        assertEquals(obj.getCveId(), "new_cve_id");
    }

    @Test
    public void testCvssScoreToString() {
        CvssScore obj = new CvssScore("cve_id", 0, 1, "impact_score", 2);
        String ref = "CvssScore(cveId=" + "cve_id" + ", severityId=" + 0 + ", severityConfidence=" + 1.0
            + ", impactScore=" + "impact_score" + ", impactConfidence=" + 2.0 + ")";

        assertEquals(obj.toString(), ref);
    }
}