package edu.rit.se.nvip.cwe;

import java.util.*;

public class CWE {
    private int id;
    private String name;
    private String description;
    private List<CWE> children;
    private List<Integer> parentIds;
    private List<CWE> parents;
    private List<CWE> siblings;

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
        this.children = new ArrayList<>();
        this.parentIds = new ArrayList<>();
        this.parents = new ArrayList<>();
        this.siblings =  new ArrayList<>();
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
     * Generates either the sibling or parent of a CWE given a list of all CWEs
     * @param list list of all CWEs
     */
    public void generateFamily(List<CWE> list){
        for (CWE cwe : list){
            if (this.getParentIds().contains(cwe.getId())){ //if this CWE's parentId matches the ID of the cwe
                cwe.addChild(this); //add this cwe to that cwe's children
                this.addParent(cwe); //make the cwe this cwe's parent
            }
            if(this.getParent() == cwe.getParent()){ //if two cwes share the same parent
                this.siblings.add(cwe); //make them siblings
            }

        }
    }
    public List<Integer> getParentIds(){return this.parentIds;}
    public List<CWE> getChildren(){return this.children;}
    public List<CWE> getSiblings(){return this.siblings;}

    public Integer getId(){return this.id;}

    public List<CWE> getParent(){return this.parents;}

    class CWETree {
        private CWE root;
        private List<CWETree> subtrees;

        public CWETree(CWE root) {
            this.root = root;
            this.subtrees = new ArrayList<>();
        }

        public void addSubtree(CWETree subtree) {
            subtrees.add(subtree);
        }

        public CWE getRoot() {
            return root;
        }

        public List<CWETree> getSubtrees() {
            return subtrees;
        }
    }

    class CWEForest {
        private List<CWETree> trees;

        public CWEForest() {
            this.trees = new ArrayList<>();
        }

        public void constructForest(Set<CWE> objects) {
            Map<CWE, CWETree> objectToTreeMap = new HashMap<>();

            for (CWE object : objects) {
                CWETree tree = new CWETree(object);
                objectToTreeMap.put(object, tree);
            }

            for (CWE cwe : objects) {
                CWETree tree = objectToTreeMap.get(cwe);
                List<CWE> parent = cwe.getParent();

                if (parent != null) {
                    CWETree parentTree = objectToTreeMap.get(parent);
                    parentTree.addSubtree(tree);
                } else {
                    trees.add(tree);
                }

                for (CWE sibling : cwe.getSiblings()) {
                    CWETree siblingTree = objectToTreeMap.get(sibling);
                    tree.addSubtree(siblingTree);
                }
            }
        }

        public List<CWETree> getTrees() {
            return trees;
        }
    }
}
