package edu.rit.se.nvip.db.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for AffectedRelease Model
 */
public class AffectedReleaseTest {
    @Test
    public void testAffectedRelease() {
        AffectedRelease obj = new AffectedRelease(0, "cve_id", "cpe", "release_date", "version");

        assertEquals(obj.getId(), 0);
        assertEquals(obj.getCveId(), "cve_id");
        assertEquals(obj.getCpe(), "cpe");
        assertEquals(obj.getReleaseDate(), "release_date");
        assertEquals(obj.getVersion(), "version");

        obj.setCveId("new_cve_id");
        obj.setReleaseDate("new_release_date");
        obj.setVersion("new_version");

        assertEquals(obj.getCveId(), "new_cve_id");
        assertEquals(obj.getReleaseDate(), "new_release_date");
        assertEquals(obj.getVersion(), "new_version");
    }

    @Test
    public void testAffectedReleaseToString() {
        AffectedRelease obj = new AffectedRelease(0, "cve_id", "cpe", "release_date", "version");
        String ref = "AffectedRelease(id=0, cveId=" + "cve_id" + ", cpe=" + "cpe" + ", releaseDate=" + "release_date" + ", version=" + "version" + ")";
        assertEquals(obj.toString(), ref);
    }

    @Test
    public void testAffectedReleaseEquals() {
        AffectedRelease obj1 = new AffectedRelease(0, "cve", "cpe", "release_date", "version");
        AffectedRelease obj2 = new AffectedRelease("cpe2", "release_date", "version");
        AffectedRelease obj3 = new AffectedRelease(obj1);

        boolean equals = obj1.equals("test");
        assertFalse(equals);

        equals = obj1.equals(obj2);
        assertFalse(equals);

        equals = obj1.equals(obj3);
        assertTrue(equals);
    }
}