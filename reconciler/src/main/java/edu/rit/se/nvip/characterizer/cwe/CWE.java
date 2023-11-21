package edu.rit.se.nvip.characterizer.cwe;


import java.util.*;

public class CWE {
    private int id;
    private String name;
    private String description;
    private Set<CWE> children;
    private Set<Integer> parentIds;
    private Set<CWE> parents;
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
            if(!(this == cwe)){
                if (this.getParentIds().contains(cwe.getId())) { //if this CWE's parentId matches the ID of the cwe
                    cwe.addChild(this); //add this cwe to that cwe's children
                    this.addParent(cwe); //make the cwe this cwe's parent
                }
            }

        }
    }
    public Set<Integer> getParentIds(){return this.parentIds;}
    public Set<CWE> getChildren(){return this.children;}
    public static Set<CWE> getAllCWEs(){return allCWEs;}
    public String getName(){ return this.name;}
    public Integer getId(){return this.id;}

    public Set<CWE> getParent(){return this.parents;}
    public String getDescription(){return this.description;}
}
