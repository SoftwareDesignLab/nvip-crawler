package edu.rit.se.nvip.cwe;

import java.util.*;

public class CWE {
    private int id;
    private String name;
    private String description;
    private Set<CWE> children;
    private Set<Integer> parentIds;
    private Set<CWE> parents;
    private Set<CWE> siblings;
    private static final Set<CWE> allCWEs = new HashSet<>();

    /**
     *
     * @param id id associated with cwe
     * @param name name associated with cwe
     * @param description extended desc associated with cwe
     */

    public CWE(int id, String name, String description){
        this.id = id;
        this.name = name;
        this.description = description;
        this.children = new HashSet<>();
        this.parentIds = new HashSet<>();
        this.parents = new HashSet<>();
        this.siblings =  new HashSet<>();
        allCWEs.add(this);
    }

    public void addParentId(int cweId){ //adds parentId to
        parentIds.add(cweId);
    }
    public void addChild(CWE cwe){
        children.add(cwe);
    }
    public void addParent(CWE cwe){
        parents.add(cwe);
    }

    /**
     * Generates either the sibling or parent of a CWE given a Set of all CWEs
     * @param set Set of all CWEs
     */
    public void generateFamily(Set<CWE> set){
        for (CWE cwe : set){
            if (this.getParentIds().contains(cwe.getId())){ //if this CWE's parentId matches the ID of the cwe
                cwe.addChild(this); //add this cwe to that cwe's children
                this.addParent(cwe); //make the cwe this cwe's parent
            }
            if(this.getParent() == cwe.getParent()){ //if two cwes share the same parent
                this.siblings.add(cwe); //make them siblings
            }

        }
    }
    public Set<Integer> getParentIds(){return this.parentIds;}
    public Set<CWE> getChildren(){return this.children;}
    public Set<CWE> getSiblings(){return this.siblings;}
    public static Set<CWE> getAllCWEs(){return allCWEs;}
    public String getName(){ return this.name;}
    public Integer getId(){return this.id;}

    public Set<CWE> getParent(){return this.parents;}

    static class CWETree {
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
            if (this.getRoot().getChildren().size() == 0) {
                return 0;
            }
            int max = this.getRoot().getChildren().size();
            for (CWETree child : this.subtrees) {
                int maxChildrenOfChild = maxChildren();
                if (maxChildrenOfChild > max) {
                    max = maxChildrenOfChild;
                }
            }
            return max;
        }
    }

    static class CWEForest {
        private Set<CWETree> trees;

        public CWEForest() {
            this.trees = new HashSet<>();
            constructForest(CWE.getAllCWEs());
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

                for (CWE sibling : cwe.getSiblings()) {
                    CWETree siblingTree = cweToTreeMap.get(sibling);
                    tree.addSubtree(siblingTree);
                }
            }
        }
        public Set<CWETree> getTrees() {
            return trees;
        }
    }
}
