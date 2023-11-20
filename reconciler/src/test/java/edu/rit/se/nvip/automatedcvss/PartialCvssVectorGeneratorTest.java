package edu.rit.se.nvip.automatedcvss;


import edu.rit.se.nvip.db.model.enums.VDOLabel;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class PartialCvssVectorGeneratorTest {
    //Tests several different CVSS Vector cases.
    @Test
    void getCVssVectorTest1(){
        PartialCvssVectorGenerator partial = new PartialCvssVectorGenerator();
        Set<VDOLabel> input = new HashSet<>();
        input.add(VDOLabel.REMOTE);
        input.add(VDOLabel.WRITE);
        input.add(VDOLabel.HPKP_HSTS);
        input.add(VDOLabel.CONTEXT_ESCAPE);
        input.add(VDOLabel.GUEST_OS);

        String[] res = partial.getCVssVector(input);

        assertEquals("N", res[0]);
        assertEquals("L", res[1]);
        assertEquals("X", res[2]);
        assertEquals("X", res[3]);
        assertEquals("C", res[4]);
        assertEquals("N", res[5]);
        assertEquals("LH", res[6]);
        assertEquals("N", res[7]);
    }
    @Test
    void getCVssVectorTest2() {
        PartialCvssVectorGenerator partial = new PartialCvssVectorGenerator();
        Set<VDOLabel> input = new HashSet<>();
        input.add(VDOLabel.LIMITED_RMT);
        input.add(VDOLabel.PRIVILEGE_ESCALATION);
        input.add(VDOLabel.SANDBOXED);
        input.add(VDOLabel.MAN_IN_THE_MIDDLE);
        input.add(VDOLabel.FIRMWARE);

        String[] res = partial.getCVssVector(input);

        assertEquals("N", res[0]);
        assertEquals("H", res[1]);
        assertEquals("X", res[2]);
        assertEquals("X", res[3]);
        assertEquals("C", res[4]);
        assertEquals("H", res[5]);
        assertEquals("N", res[6]);
        assertEquals("N", res[7]);
    }

    @Test
    void getCVssVectorTest3() {
        PartialCvssVectorGenerator partial = new PartialCvssVectorGenerator();
        Set<VDOLabel> input = new HashSet<>();
        input.add(VDOLabel.REMOTE);

        String[] res = partial.getCVssVector(input);

        assertEquals("N", res[0]);
        assertEquals("L", res[1]);
        assertEquals("X", res[2]);
        assertEquals("X", res[3]);
        assertEquals("U", res[4]);
        assertEquals("N", res[5]);
        assertEquals("N", res[6]);
        assertEquals("N", res[7]);
    }

    @Test
    void getCVssVectorTest4() {
        PartialCvssVectorGenerator partial = new PartialCvssVectorGenerator();
        Set<VDOLabel> input = new HashSet<>();
        input.add(VDOLabel.LOCAL);
        input.add(VDOLabel.READ);
        input.add(VDOLabel.MULTIFACTOR_AUTHENTICATION);
        input.add(VDOLabel.CONTEXT_ESCAPE);
        input.add(VDOLabel.CHANNEL);

        String[] res = partial.getCVssVector(input);

        assertEquals("L", res[0]);
        assertEquals("L", res[1]);
        assertEquals("X", res[2]);
        assertEquals("X", res[3]);
        assertEquals("C", res[4]);
        assertEquals("LH", res[5]);
        assertEquals("N", res[6]);
        assertEquals("N", res[7]);
    }
    @Test
    void getCVssVectorTest6(){
        PartialCvssVectorGenerator partial = new PartialCvssVectorGenerator();
        Set<VDOLabel> input = new HashSet<>();
        input.add(VDOLabel.LOCAL);
        input.add(VDOLabel.SERVICE_INTERRUPT);
        input.add(VDOLabel.ASLR);
        input.add(VDOLabel.CONTEXT_ESCAPE);
        input.add(VDOLabel.HYPERVISOR);

        String[] res = partial.getCVssVector(input);

        assertEquals("L", res[0]);
        assertEquals("L", res[1]);
        assertEquals("X", res[2]);
        assertEquals("X", res[3]);
        assertEquals("C", res[4]);
        assertEquals("N", res[5]);
        assertEquals("N", res[6]);
        assertEquals("LH", res[7]);
    }
}