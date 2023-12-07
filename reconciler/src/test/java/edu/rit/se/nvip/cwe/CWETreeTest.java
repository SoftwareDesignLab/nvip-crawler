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
import edu.rit.se.nvip.characterizer.cwe.CWETree;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CWETreeTest {

    //verifies subtrees are added correctly
    @Test
    void addSubtree() {
        CWE root = new CWE(1, "1", "desc");
        CWE root2 = new CWE(1, "1", "desc");
        CWETree tree = new CWETree(root);
        CWETree subTree = new CWETree(root2);
        tree.addSubtree(subTree);

        assertEquals(1, tree.getSubtrees().size());

    }

    //verifies that the maximum amount of children is found properly
    //where the maximum amount of children is grabbed from the CWE that has the most children
    @Test
    void maxChildren() {
        CWE root = new CWE(1, "1", "desc");
        CWE root2 = new CWE(2, "1", "desc");
        CWE root3 = new CWE(3, "1", "desc");
        CWE root4 = new CWE(4, "1", "desc");
        root.addChild(root2);
        root.addChild(root3);
        root.addChild(root4);
        CWETree tree = new CWETree(root);
        CWETree tree2 = new CWETree(root4);
        tree.addSubtree(tree2);

        assertEquals(3, tree.maxChildren());
    }
}