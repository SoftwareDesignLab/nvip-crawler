package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SimpleFilterTest {

    private RawVulnerability genRawVuln(int id) {
        return new RawVulnerability(id, "", "description"+id, null, null, null, "" );
    }

    @Test
    void passesFilter() {
        Filter filter = new SimpleFilter();
        Set<RawVulnerability> vulns = new HashSet<>();
        for (int i = 0; i < 10; i++) {
            vulns.add(genRawVuln(i));
        }
        Set<RawVulnerability> filtered = filter.filterAll(vulns);
        assertEquals(0, filtered.size());
        assertEquals(10, vulns.size());
    }
}