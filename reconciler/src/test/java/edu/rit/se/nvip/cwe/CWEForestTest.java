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
import edu.rit.se.nvip.characterizer.cwe.CWEForest;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CWEForestTest {

    //verifies that the forest is constructed and that parents/children are assigned correctly
    @Test
    void constructForest() {
        CWEForest forest = new CWEForest();
        CWE cwe = new CWE(1, "cwe", "desc");
        CWE cwe1 = new CWE(2, "cwe", "desc");
        CWE cwe2 = new CWE(3, "cwe", "desc");
        CWE cwe3 = new CWE(4, "cwe", "desc");
        CWE cwe4 = new CWE(5, "cwe", "desc");
        cwe.addParent(cwe1);
        cwe2.addParent(cwe1);
        cwe3.addParent(cwe);
        cwe4.addParent(cwe);
        Set<CWE> set = new HashSet<>();
        set.add(cwe);
        set.add(cwe1);
        set.add(cwe2);
        set.add(cwe3);
        set.add(cwe4);

        forest.constructForest(set);

        assertEquals(1, forest.getTrees().size());
        //cwe1 is the top of the tree with children cwe2 and cwe and cwe has children cwe3 and cwe4
        //      cwe1
        //   cwe    cwe2
        //cwe3 cwe4
    }
}