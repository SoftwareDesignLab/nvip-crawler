package model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CompositeDescriptionTest {
    private final int dummyId;
    private final String dummyCveId;
    private final String dummyDescription;
    private final Timestamp dummyCreateDate;
    private final String dummyBuildString;
    private final long dummyMillis;
    private final Clock mockClock;

    CompositeDescriptionTest() {
        this.dummyId = 1;
        this.dummyCveId = "CVE-xxxx-xxx";
        this.dummyDescription = "composite description";
        this.dummyBuildString = "(((1,2,3),4,5),6)";
        this.dummyMillis = Instant.now().toEpochMilli();
        this.mockClock = mock(Clock.class);
        this.dummyCreateDate = new Timestamp(dummyMillis);
        CompositeDescription.setClock(mockClock);
    }
    @BeforeEach
    void resetMocks() {
        when(mockClock.millis()).thenReturn(dummyMillis);
    }

    private RawVulnerability genRawVuln(int id) {
        return new RawVulnerability(id, "", "description"+id, null, null, null, "" );
    }
    private Set<RawVulnerability> genRawVulns(int size, int startId) {
        Set<RawVulnerability> out = new LinkedHashSet<>();
        for (int i = 0; i < size; i++) {
            out.add(genRawVuln(i+startId));
        }
        return out;
    }

    private CompositeDescription genCompDes(String buildString, int nSources) {
        return new CompositeDescription(dummyId, dummyCveId, dummyDescription, dummyCreateDate, buildString, genRawVulns(nSources, 1));
    }

    private CompositeDescription genCompDes() {
        return genCompDes(dummyBuildString, 6);
    }

    @Test
    void constuctorFromFields() {
        CompositeDescription compDes = genCompDes();
        assertEquals(dummyId, compDes.getId());
        assertEquals(dummyDescription, compDes.getDescription());
        assertEquals(dummyCreateDate, compDes.getCreatedDate());
        assertEquals(dummyBuildString, compDes.getBuildString());
        assertEquals(6, compDes.getSources().size());
    }

    @Test
    void constructorFromSources() {
        Set<RawVulnerability> rawVulns = genRawVulns(6, 1);
        CompositeDescription compDes = new CompositeDescription(dummyCveId, dummyDescription, rawVulns);
        assertEquals(0, compDes.getId());
        assertEquals(dummyDescription, compDes.getDescription());
        assertEquals(dummyCreateDate, compDes.getCreatedDate());
        assertEquals("(1,2,3,4,5,6)", compDes.getBuildString());
        assertEquals(6, compDes.getSources().size());
    }

    @Test
    void constructorFromSource() {
        CompositeDescription compDes = new CompositeDescription(genRawVuln(1));
        assertEquals(0, compDes.getId());
        assertEquals("description1", compDes.getDescription());
        assertEquals(dummyCreateDate, compDes.getCreatedDate());
        assertEquals("1", compDes.getBuildString());
        assertEquals(1, compDes.getSources().size());
    }

    @Test
    void getDescription() {
        CompositeDescription compDes = genCompDes();
        assertEquals(dummyDescription, compDes.getDescription());
        compDes.addSources("new description", genRawVulns(1, 7));
        assertEquals("new description", compDes.getDescription());
        compDes.addSourcesAndResynth("new new description", genRawVulns(1, 8));
        assertEquals("new new description", compDes.getDescription());
    }

    @Test
    void getId() {
        CompositeDescription compDes = genCompDes();
        assertEquals(dummyId, compDes.getId());
        compDes.setId(5);
        assertEquals(5, compDes.getId());
    }

    @Test
    void setId() {
        CompositeDescription compDes = genCompDes();
        compDes.setId(10);
        assertEquals(10, compDes.getId());
    }

    @Test
    void getCreatedDate() {
        CompositeDescription compDes = genCompDes();
        assertEquals(dummyCreateDate, compDes.getCreatedDate());
        when(mockClock.millis()).thenReturn(dummyMillis + 1000L);
        compDes.addSources("blah", genRawVulns(1, 8));
        assertEquals(new Timestamp(dummyMillis + 1000L), compDes.getCreatedDate());
    }

    @Test
    void getBuildString() {
        CompositeDescription compDes = genCompDes("(1,2,3)", 3);
        assertEquals("(1,2,3)", compDes.getBuildString());
        compDes.addSources("blah", genRawVulns(2, 4));
        assertEquals("((1,2,3),4,5)", compDes.getBuildString());
        compDes.addSourcesAndResynth("blah2", genRawVulns(4, 6));
        assertEquals("(1,2,3,4,5,6,7,8,9)", compDes.getBuildString());
        compDes.addSources("blah3", genRawVulns(1, 10));
        assertEquals("((1,2,3,4,5,6,7,8,9),10)", compDes.getBuildString());
    }

    @Test
    void addSources() {
        CompositeDescription compDes = genCompDes();
        compDes.addSources("new description", genRawVulns(3, 7));
        assertEquals("new description", compDes.getDescription());
        assertEquals(9, compDes.getSources().size());
        assertEquals("(" + dummyBuildString + ",7,8,9)", compDes.getBuildString());
    }

    @Test
    void addSourcesAndResynth() {
        CompositeDescription compDes = genCompDes();
        compDes.addSourcesAndResynth("new description", genRawVulns(3, 7));
        assertEquals("new description", compDes.getDescription());
        assertEquals(9, compDes.getSources().size());
        assertEquals("(1,2,3,4,5,6,7,8,9)", compDes.getBuildString());
    }

    @Test
    void getSources() {
        CompositeDescription compDes = genCompDes();
        Set<RawVulnerability> sources = compDes.getSources();
        assertEquals(6, sources.size());
    }
}