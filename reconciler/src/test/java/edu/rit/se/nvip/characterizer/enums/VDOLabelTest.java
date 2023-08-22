package edu.rit.se.nvip.characterizer.enums;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VDOLabelTest {

    //simply verifies that you can get a VDOLabel from its name
    @Test
    void getVdoLabel() {
        for(VDOLabel vdo : VDOLabel.values()){
            VDOLabel gottenVDO = VDOLabel.getVdoLabel(vdo.vdoLabelName);
            assertEquals(vdo, gottenVDO);
        }

    }
}