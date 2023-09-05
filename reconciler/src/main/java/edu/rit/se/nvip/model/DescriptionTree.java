package edu.rit.se.nvip.model;

import java.util.*;
import java.util.stream.Collectors;

public class DescriptionTree {

    private static final char SEPARATOR = ',';
    private static final char OPEN_PAREN = '(';
    private static final char CLOSE_PAREN = ')';
    public static class Node {
        RawVulnerability vuln;
        List<Node> children;

        public Node(RawVulnerability vuln) {
            this.vuln = vuln;
            this.children = new ArrayList<>();
        }

        public boolean isLeaf() {
            return this.vuln != null;
        }

        @Override
        public String toString() {
            if (this.isLeaf()) {
                return this.vuln.getIdString();
            } else {
                StringBuilder sb = new StringBuilder(""+OPEN_PAREN);
                for (int i = 0; i < this.children.size(); i++) {
                    sb.append(this.children.get(i).toString());
                    if (i < this.children.size() -  1) {
                        sb.append(""+SEPARATOR);
                    }
                }
                sb.append(""+CLOSE_PAREN);
                return sb.toString();
            }
        }
        public boolean equalUpToOrder(Node that) {
            if (this.isLeaf()) {
                if (!that.isLeaf()) {
                    return false;
                }
                return this.vuln.getId() == that.vuln.getId();
            }
            if (this.children.size() != that.children.size()) {
                return false;
            }
            Set<Node> matchedOtherChildren = new HashSet<>();
            for (Node child : this.children) {
                boolean matched = false;
                for (Node otherChild : that.children) {
                    if (child.equalUpToOrder(otherChild) && !matchedOtherChildren.contains(otherChild)) {
                        matchedOtherChildren.add(otherChild);
                        matched = true;
                        break;
                    }
                }
                if (!matched) {return false;}
            }
            return true;
        }
    }

    private Node root;
    public DescriptionTree() {
        this.root = new Node(null);
    }
    public DescriptionTree (String buildString, Set<RawVulnerability> vulns) {
        Map<Integer, RawVulnerability> idToVuln = new HashMap<>();
        vulns.forEach(v->idToVuln.put(v.getId(), v));
        this.root = buildTreeFromString(buildString, idToVuln);
    }
    public DescriptionTree(RawVulnerability vuln) {
        this.root = new Node(null);
        this.root.children.add(new Node(vuln));
    }
    public DescriptionTree(List<RawVulnerability> vulns) {
        this.root = new Node(null);
        for (RawVulnerability vuln : vulns) {
            this.root.children.add(new Node(vuln));
        }
    }
    public void addTopSibling(RawVulnerability vuln) {
        List<RawVulnerability> list = new ArrayList<>();
        list.add(vuln);
        this.addTopSiblings(list);
    }
    public void addTopSiblings(List<RawVulnerability> vulns) {
        Node newRoot;
        // if this is a leafless tree, don't need to make a new parent root
        // or if we have nothing to add, don't need to make a new parent root
        // or if the tree is just a root and a single leaf, the new ones get added as siblings to the leaf, not the inner node
        if (this.root.children.size() == 0 || vulns.size() == 0 || (this.root.children.size() == 1 && this.root.children.get(0).isLeaf())) {
            newRoot = this.root;
        } else {
            newRoot = new Node(null);
            newRoot.children.add(this.root);
        }
        for (RawVulnerability vuln : vulns) {
            newRoot.children.add(new Node(vuln));
        }
        this.root = newRoot;
    }

    private Node buildTreeFromString(String s, Map<Integer, RawVulnerability> map) {
        Node node = new Node(null);
        // buildstrings should always start and end with parens, but past implementations might have left behind buildstrings of the form "i", this fixes those
        if (s.charAt(0) != OPEN_PAREN) {
            node.children.add(new Node(map.get(Integer.parseInt(s))));
            return node;
        }
        // remove outer parens
        s = s.substring(1, s.length() - 1);
        if (s.isEmpty()) {
            return node;
        }
        int parenCount = 0;
        int lastCommaIndex = -1;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == OPEN_PAREN) {
                parenCount++;
            } else if (s.charAt(i) == CLOSE_PAREN) {
                parenCount--;
            }
            if (parenCount == 0 && (s.charAt(i) == SEPARATOR || i == s.length() - 1)) {
                String sub = i == s.length() - 1 ? s.substring(lastCommaIndex+1) : s.substring(lastCommaIndex+1,i);
                if (sub.startsWith(""+OPEN_PAREN)) {
                    node.children.add(buildTreeFromString(sub, map));
                } else {
                    node.children.add(new Node(map.get(Integer.parseInt(sub))));
                }
                lastCommaIndex = i;
            }
        }
        return node;
    }

    public boolean equalUpToOrder(DescriptionTree other) {
        return this.root.equalUpToOrder(other.root);
    }

    @Override
    public String toString() {
        return this.root.toString();
    }

    public static boolean equivalentBuildStrings(String s1, String s2, Set<RawVulnerability> vulns) {
        DescriptionTree tree1 = new DescriptionTree(s1, vulns);
        DescriptionTree tree2 = new DescriptionTree(s2, vulns);
        return tree1.equalUpToOrder(tree2);
    }

    public static void main(String[] args) {
        DescriptionTree dt = new DescriptionTree("(1)", gen(3));
        System.out.println(dt);
    }

    private static Set<RawVulnerability> gen(int n) {
        Set<RawVulnerability> map = new HashSet<>();
        for (int i = 1; i <= n; i++) {
            map.add(new RawVulnerability(i, "", "", null, null, null, ""));
        }
        return map;
    }
}
