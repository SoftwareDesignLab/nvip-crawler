package edu.rit.se.nvip.characterizer.cwe;

import java.util.HashSet;
import java.util.Set;

public class CWETree {
        private CWE root;
        private Set<CWETree> subtrees;

        public CWETree(CWE root) {
            this.root = root;
            this.subtrees = new HashSet<>();
        }

        public void addSubtree(CWETree subtree) {
            subtrees.add(subtree);
        }

        public CWE getRoot() {
            return root;
        }

        public Set<CWETree> getSubtrees() {
            return subtrees;
        }
        public int maxChildren() {
            if (this.getRoot().getChildren().isEmpty()) {
                return 0;
            }
            int max = this.getRoot().getChildren().size();
            for (CWETree child : this.subtrees) {
                int maxChildrenOfChild = child.maxChildren();
                if (maxChildrenOfChild > max) {
                    max = maxChildrenOfChild;
                }
            }
            return max;
        }
}
