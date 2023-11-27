package edu.rit.se.nvip.characterizer.cwe;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CWEForest {
    private Set<CWETree> trees;

    public CWEForest() {
        this.trees = new HashSet<>();
    }

    public void constructForest(Set<CWE> cwes) {
        Map<CWE, CWETree> cweToTreeMap = new HashMap<>();

        for (CWE cwe : cwes) {
            CWETree tree = new CWETree(cwe);
            cweToTreeMap.put(cwe, tree);
        }

        for (CWE cwe : cwes) {
            CWETree tree = cweToTreeMap.get(cwe);
            Set<CWE> cweParents = cwe.getParent();

            if (!cweParents.isEmpty()) {
                for (CWE parent : cweParents) {
                    CWETree parentTree = cweToTreeMap.get(parent);
                    parentTree.addSubtree(tree);
                }
            } else {
                trees.add(tree);
            }

        }
    }
    public Set<CWETree> getTrees() {
        return trees;
    }
}
