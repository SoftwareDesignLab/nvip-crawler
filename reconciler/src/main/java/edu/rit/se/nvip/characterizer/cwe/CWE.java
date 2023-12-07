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
