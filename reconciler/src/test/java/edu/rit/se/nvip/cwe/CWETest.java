/ **
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
* /

package edu.rit.se.nvip.cwe;

import edu.rit.se.nvip.characterizer.cwe.CWE;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CWETest {

    //verifies you can add a parent id correctly

    @Test
    void addParentId() {
        CWE cwe = new CWE(1, "cwe", "desc");
        CWE parent = new CWE(2, "parentCWE", "desc");

        cwe.addParentId(parent.getId());
        List<Integer> list = new ArrayList<>(cwe.getParentIds());
        assertEquals(parent.getId(), list.get(0));
    }
    //verifies you can add a child correctly
    @Test
    void addChild() {
        CWE cwe = new CWE(1, "cwe", "desc");
        CWE child = new CWE(2, "childCWE", "desc");

        cwe.addChild(child);
        List<CWE> list = new ArrayList<>(cwe.getChildren());
        assertEquals(child.getId(), list.get(0).getId());
    }
    //verifies you can add a parent correctly
    @Test
    void addParent() {
        CWE cwe = new CWE(1, "cwe", "desc");
        CWE parent = new CWE(2, "parentCWE", "desc");

        cwe.addParent(parent);
        List<CWE> list = new ArrayList<>(cwe.getParent());
        assertEquals(parent.getId(), list.get(0).getId());
    }
    //verifies you can generate a family if you are given CWEs with parent ids assigned.
    //works sort of like constructforest for cweforest but this just sets children and parents
    @Test
    void generateFamily() {
        CWE cwe = new CWE(1, "cwe", "desc");
        CWE cwe1 = new CWE(2, "cwe", "desc");
        CWE cwe2 = new CWE(3, "cwe", "desc");
        CWE cwe3 = new CWE(4, "cwe", "desc");
        CWE cwe4 = new CWE(5, "cwe", "desc");
        cwe.addParentId(cwe1.getId());
        cwe2.addParentId(cwe1.getId());
        cwe3.addParentId(cwe.getId());
        cwe4.addParentId(cwe.getId());
        Set<CWE> set = new HashSet<>();
        set.add(cwe);
        set.add(cwe1);
        set.add(cwe2);
        set.add(cwe3);
        set.add(cwe4);

        for(CWE cw : set){
            cw.generateFamily(set);
        }

        assertEquals(2, cwe.getChildren().size());
        assertEquals(2, cwe1.getChildren().size());
        assertEquals(0, cwe3.getChildren().size());
        assertEquals(0, cwe4.getChildren().size());
    }
}