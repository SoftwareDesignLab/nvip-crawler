/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

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