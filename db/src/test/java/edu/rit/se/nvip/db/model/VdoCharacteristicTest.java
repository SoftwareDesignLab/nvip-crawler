package edu.rit.se.nvip.db.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for VdoCharacteristic Model
 */
public class VdoCharacteristicTest {
    @Test
    public void testVdo() {
        VdoCharacteristic obj = new VdoCharacteristic("cve_id", 0, 1, 2);
        assertEquals(obj.getCveId(), "cve_id");
        assertEquals(obj.getVdoLabelId(), 0);
        assertEquals(obj.getVdoConfidence(), 1, 0.01);
        assertEquals(obj.getVdoNounGroupId(), 2);

        obj.setCveId("new_cve_id");

        assertEquals(obj.getCveId(), "new_cve_id");
    }

    @Test
    public void testVdoToString() {
        VdoCharacteristic obj = new VdoCharacteristic("cve_id", 0, 1, 2);
        String ref = "VdoCharacteristic(cveId=" + "cve_id" + ", vdoLabelId=" + 0 + ", vdoConfidence=" + 1.0 + ", vdoNounGroupId=2)";
        assertEquals(obj.toString(), ref);
    }
}