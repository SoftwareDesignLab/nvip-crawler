package edu.rit.se.nvip.automatedcvss;

import edu.rit.se.nvip.characterizer.enums.VDOLabel;
import edu.rit.se.nvip.characterizer.enums.VDONounGroup;
import org.apache.commons.collections.list.SynchronizedList;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PartialCvssVectorGeneratorTest {
    //Tests several different CVSS Vector cases.
    @Test
    void getCVssVectorTest1(){
        PartialCvssVectorGenerator partial = new PartialCvssVectorGenerator();
        Map<VDONounGroup, Map<VDOLabel, Double>> input = new HashMap<>();
        double count = 1.0;
        List<VDOLabel> list = new ArrayList<>();
        list.add(VDOLabel.REMOTE);
        list.add(VDOLabel.WRITE);
        list.add(VDOLabel.WRITE);
        list.add(VDOLabel.CONTEXT_ESCAPE);
        list.add(VDOLabel.SERVICE_INTERRUPT);
        List<Map<VDOLabel, Double>> maps = new ArrayList<>();
        for(VDOLabel vdo : list) {
            Map<VDOLabel, Double> map = new HashMap<>();
            map.put(vdo, count++);
            maps.add(map);
        }
        input.put(VDONounGroup.ATTACK_THEATER, maps.get(0));
        input.put(VDONounGroup.LOGICAL_IMPACT, maps.get(1));
        input.put(VDONounGroup.MITIGATION, maps.get(2));
        input.put(VDONounGroup.IMPACT_METHOD, maps.get(3));
        input.put(VDONounGroup.CONTEXT, maps.get(3));

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
        Map<VDONounGroup, Map<VDOLabel, Double>> input = new HashMap<>();
        double count = 1.0;
        List<VDOLabel> list = new ArrayList<>();
        list.add(VDOLabel.LIMITED_RMT);
        list.add(VDOLabel.PRIVILEGE_ESCALATION);
        list.add(VDOLabel.SANDBOXED);
        list.add(VDOLabel.MAN_IN_THE_MIDDLE);
        list.add(VDOLabel.SERVICE_INTERRUPT);
        List<Map<VDOLabel, Double>> maps = new ArrayList<>();
        for(VDOLabel vdo : list) {
            Map<VDOLabel, Double> map = new HashMap<>();
            map.put(vdo, count++);
            maps.add(map);
        }
        input.put(VDONounGroup.ATTACK_THEATER, maps.get(0));
        input.put(VDONounGroup.LOGICAL_IMPACT, maps.get(1));
        input.put(VDONounGroup.MITIGATION, maps.get(2));
        input.put(VDONounGroup.IMPACT_METHOD, maps.get(3));
        input.put(VDONounGroup.CONTEXT, maps.get(3));

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
        Map<VDONounGroup, Map<VDOLabel, Double>> input = new HashMap<>();



        Map<VDOLabel, Double> map = new HashMap<>();
        map.put(VDOLabel.REMOTE, 1.0);

        input.put(VDONounGroup.CONTEXT, map);

        String[] res = partial.getCVssVector(input);

        assertEquals("X", res[0]);
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
        Map<VDONounGroup, Map<VDOLabel, Double>> input = new HashMap<>();
        double count = 1.0;
        List<VDOLabel> list = new ArrayList<>();
        list.add(VDOLabel.LOCAL);
        list.add(VDOLabel.READ);
        list.add(VDOLabel.WRITE);
        list.add(VDOLabel.CONTEXT_ESCAPE);
        list.add(VDOLabel.SERVICE_INTERRUPT);
        List<Map<VDOLabel, Double>> maps = new ArrayList<>();
        for(VDOLabel vdo : list) {
            Map<VDOLabel, Double> map = new HashMap<>();
            map.put(vdo, count++);
            maps.add(map);
        }
        input.put(VDONounGroup.ATTACK_THEATER, maps.get(0));
        input.put(VDONounGroup.LOGICAL_IMPACT, maps.get(1));
        input.put(VDONounGroup.MITIGATION, maps.get(2));
        input.put(VDONounGroup.IMPACT_METHOD, maps.get(3));
        input.put(VDONounGroup.CONTEXT, maps.get(3));

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
        Map<VDONounGroup, Map<VDOLabel, Double>> input = new HashMap<>();
        double count = 1.0;
        List<VDOLabel> list = new ArrayList<>();
        list.add(VDOLabel.LOCAL);
        list.add(VDOLabel.SERVICE_INTERRUPT);
        list.add(VDOLabel.WRITE);
        list.add(VDOLabel.CONTEXT_ESCAPE);
        list.add(VDOLabel.SERVICE_INTERRUPT);
        List<Map<VDOLabel, Double>> maps = new ArrayList<>();
        for(VDOLabel vdo : list) {
            Map<VDOLabel, Double> map = new HashMap<>();
            map.put(vdo, count++);
            maps.add(map);
        }
        input.put(VDONounGroup.ATTACK_THEATER, maps.get(0));
        input.put(VDONounGroup.LOGICAL_IMPACT, maps.get(1));
        input.put(VDONounGroup.MITIGATION, maps.get(2));
        input.put(VDONounGroup.IMPACT_METHOD, maps.get(3));
        input.put(VDONounGroup.CONTEXT, maps.get(3));

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