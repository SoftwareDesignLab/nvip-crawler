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

    private boolean isUserGenerated = false;

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
        this.descriptionTree = new DescriptionTree(buildString, sources);
        this.sources = sources;
    }

    public CompositeDescription(String cveId, String description, Set<RawVulnerability> sources) {
        this.id = 0;
        this.cveId = cveId;
        this.description = description;
        setCreateDateCurrent();
        this.descriptionTree = new DescriptionTree(new ArrayList<>(sources));
        this.sources = new HashSet<>(sources);
    }

    public CompositeDescription(String cveId) {
        this(cveId, "", new HashSet<>());
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
        this.descriptionTree = new DescriptionTree(newSingleSource);
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
            return "()";
        }
        return this.descriptionTree.toString();
    }

    public String getCveId() {
        return this.cveId;
    }

    public void addSources(String description, Set<RawVulnerability> rawVulns) {
        this.sources.addAll(rawVulns);
        this.descriptionTree.addTopSiblings(new ArrayList<>(rawVulns));
        this.description = description;
        setCreateDateCurrent();
    }

    public void addSourcesAndResynth(String description, Set<RawVulnerability> rawVulns) {
        this.sources.addAll(rawVulns);
        this.descriptionTree = new DescriptionTree(new ArrayList<>(sources));
        this.description = description;
        setCreateDateCurrent();
    }

    public void reset() {
        this.sources.clear();
        this.description = "";
        this.descriptionTree = new DescriptionTree();
        setCreateDateCurrent();
    }

    public Set<RawVulnerability> getSources() {
        return this.sources;
    }

    public Set<String> getSourceUrls() {
        return this.sources.stream().map(RawVulnerability::getSourceUrl).collect(Collectors.toSet());
    }

    public boolean usesHighPrio() {
        for (RawVulnerability vuln : sources) {
            if (vuln.isHighPriority()) return true;
        }
        return false;
    }

    public boolean isUserGenerated() {
        return this.isUserGenerated;
    }

    public void setIsUserGenerated(boolean isUserGenerated) {
        this.isUserGenerated = isUserGenerated;
    }

    // Cloneable interface is annoying with final fields, doing this instead
    public CompositeDescription duplicate() {
        return new CompositeDescription(0, this.cveId, this.description, getCurrentTime(),
                this.getBuildString(), new HashSet<>(this.sources));
    }
}
