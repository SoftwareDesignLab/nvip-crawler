package edu.rit.se.nvip.cwe;

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