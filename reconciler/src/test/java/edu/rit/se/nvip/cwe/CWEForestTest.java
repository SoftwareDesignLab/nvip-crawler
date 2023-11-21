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