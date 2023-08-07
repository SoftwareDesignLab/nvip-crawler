package edu.rit.se.nvip.model;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Model of a row in the description table, including the RawVulnerabilities it's linked to through the rawdescriptionjt table.
 * It is composite in the sense that its description is built as described by the buildString from a set of RawDescriptions
 */
public class CompositeDescription {
    private static Clock CLOCK = Clock.systemDefaultZone();
    private String description;
    private int id;
    private String cveId;
    private Timestamp createdDate;
    private final Set<RawVulnerability> sources;

    private DescriptionTree descriptionTree;

    /**
     * Builds a CompositeDescription from scratch, should be used when pulling from the database table
     * @param id unique identifier, primary key in the description table
     * @param description Description of the vulnerability
     * @param createdDate The date this description was created
     * @param buildString string representation of the description build tree
     * @param sources Set of RawVulnerabilities referenced in the buildstring
     */
    public CompositeDescription(int id, String cveId, String description, Timestamp createdDate, String buildString, Set<RawVulnerability> sources) {
        this.id = id;
        this.cveId = cveId;
        this.description = description;
        this.createdDate = createdDate;
        this.descriptionTree = new DescriptionTree(buildString);
        this.sources = sources;
    }

    public CompositeDescription(String cveId, String description, Set<RawVulnerability> sources) {
        this.id = 0;
        this.cveId = cveId;
        this.description = description;
        setCreateDateCurrent();
        this.descriptionTree = new DescriptionTree(null, sources.stream().map(DescriptionTree::new).collect(Collectors.toList()));
        this.sources = new HashSet<>(sources);
    }

    /**
     * Creates a CompositeDescription from a single source by copying relevant fields
     * @param newSingleSource A RawVulnerability to build a CompositeDescription from
     */
    public CompositeDescription(RawVulnerability newSingleSource) {
        this.id = 0;
        this.cveId = newSingleSource.getCveId();
        this.description = newSingleSource.getDescription();
        setCreateDateCurrent();
        this.descriptionTree = new DescriptionTree(newSingleSource.getIdString());
        Set<RawVulnerability> vulnSet = new HashSet<>();
        vulnSet.add(newSingleSource);
        this.sources = vulnSet;
    }

    public static void setClock(Clock clock) {
        CLOCK = clock;
    }

    private void setCreateDateCurrent() {
        this.createdDate = getCurrentTime();
    }
    private Timestamp getCurrentTime() {
        return new Timestamp(CLOCK.millis());
    }

    public String getDescription() {
        return description;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public Timestamp getCreatedDate() {
        return createdDate;
    }

    public String getBuildString() {
        if (descriptionTree == null) {
            return "";
        }
        return this.descriptionTree.toString();
    }

    public String getCveId() {
        return this.cveId;
    }

    public void addSources(String description, Set<RawVulnerability> rawVulns) {
        this.sources.addAll(rawVulns);
        this.descriptionTree = new DescriptionTree(this.descriptionTree, rawVulns.stream().map(DescriptionTree::new).collect(Collectors.toList()));
        this.description = description;
        setCreateDateCurrent();
    }

    public void addSourcesAndResynth(String description, Set<RawVulnerability> rawVulns) {
        this.sources.addAll(rawVulns);
        this.descriptionTree = new DescriptionTree(null, this.sources.stream().map(DescriptionTree::new).collect(Collectors.toList()));
        this.description = description;
        setCreateDateCurrent();
    }

    public void reset() {
        this.sources.clear();
        this.description = "";
        this.descriptionTree = null;
        setCreateDateCurrent();
    }

    public Set<RawVulnerability> getSources() {
        return this.sources;
    }

    public boolean usesHighPrio() {
        for (RawVulnerability vuln : sources) {
            if (vuln.isHighPriority()) return true;
        }
        return false;
    }

    // Cloneable interface is annoying with final fields, doing this instead
    public CompositeDescription duplicate() {
        return new CompositeDescription(0, this.cveId, this.description, getCurrentTime(),
                this.getBuildString(), new HashSet<>(this.sources));
    }

    /**
     * Models the build tree for a description.
     */
    protected static class DescriptionTree {
        private int rawDescriptionId = 0;
        private List<DescriptionTree> children;
        private static final char SEPARATOR = ',';
        private static final char OPEN_PAREN = '(';
        private static final char CLOSE_PAREN = ')';

        /**
         * Makes a new tree consisting of an existing tree and a list of siblings.
         * Uses 2 args instead of just one list for convenience because of how these will be used
         * @param tree leftmost tree
         * @param siblings more siblings, inserted left to right
         */
        public DescriptionTree(DescriptionTree tree, List<DescriptionTree> siblings) {
            this.children = new ArrayList<>();
            if (tree != null) {
                this.children.add(tree);
            }
            this.children.addAll(siblings);
        }

        /**
         * Constructs the tree from a string representation as matching a toString() output
         * @param buildString string representation of the tree. e.g. (((id1, id2), id3, id4), id5)
         */
        public DescriptionTree(String buildString) {
            this.children = new ArrayList<>();
            if (buildString.charAt(0) == OPEN_PAREN) {
                int count = 0;
                int start = 1;
                for (int i = 1; i < buildString.length(); i++) {
                    char c = buildString.charAt(i);
                    if (c == OPEN_PAREN) {
                        count++;
                    } else if (c == CLOSE_PAREN) {
                        count--;
                    } else if (c == SEPARATOR && count == 0) {
                        String part = buildString.substring(start, i);
                        DescriptionTree child = new DescriptionTree(part);
                        addChild(child);
                        start = i + 1;
                    }
                }
                String lastPart = buildString.substring(start, buildString.length() - 1);
                DescriptionTree lastChild = new DescriptionTree(lastPart);
                addChild(lastChild);
            } else {
                this.rawDescriptionId = Integer.parseInt(buildString);
            }
        }

        /**
         * Builds a description tree from a single raw vulnerability (i.e. the output is a single node)
         * @param rawVuln
         */
        public DescriptionTree(RawVulnerability rawVuln) {
            this.rawDescriptionId = rawVuln.getId();
            this.children = new ArrayList<>();
        }

        private void addChild(DescriptionTree child) {
            this.children.add(child);
        }

        public int size() {
            if (children.size() == 0) {
                return 0;
            }
            return children.stream().mapToInt(DescriptionTree::size).sum();
        }

        @Override
        public String toString() {
            if (children.size() == 0) {
                return String.valueOf(rawDescriptionId);
            }
            return OPEN_PAREN + children.stream().map(DescriptionTree::toString).collect(Collectors.joining("" + SEPARATOR)) + CLOSE_PAREN;
        }

        public boolean equalUpToOrder(DescriptionTree that) {
            if (this.size() == 0) {
                if (that.size() == 0) {
                    return this.rawDescriptionId == that.rawDescriptionId;
                }
                return false;
            }
            if (this.children.size() != that.children.size()) {
                return false;
            }
            Set<DescriptionTree> matchedOtherChildren = new HashSet<>();
            for (DescriptionTree child : this.children) {
                boolean matched = false;
                for (DescriptionTree otherChild : that.children) {
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

    public static boolean equivalentBuildStrings(String s1, String s2) {
        DescriptionTree tree1 = new DescriptionTree(s1);
        DescriptionTree tree2 = new DescriptionTree(s2);
        return tree1.equalUpToOrder(tree2);
    }
}
