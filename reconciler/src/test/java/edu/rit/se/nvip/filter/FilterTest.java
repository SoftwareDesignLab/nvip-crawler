package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class FilterTest {


    private RawVulnerability genRawVuln(int id) {
        return new RawVulnerability(id, "", "description" + id, null, null, null, "");
    }

    @Test
    void filterAll() {
        Filter parityFilter = new Filter() {
            @Override
            public boolean passesFilter(RawVulnerability rawVuln) {
                return rawVuln.getId() % 2 == 0;
            }
        };
        Set<RawVulnerability> vulns = new LinkedHashSet<>();
        for (int i = 0; i < 6; i++) {
            vulns.add(genRawVuln(i));
        }
        Set<RawVulnerability> filtered = parityFilter.filterAll(vulns);
        assertEquals(3, filtered.size());
        assertEquals(3, vulns.size());
        for (RawVulnerability rawVuln : vulns) {
            if (rawVuln.getId() % 2 != 0) {
                fail();
            }
        }
        for (RawVulnerability rawVuln : filtered) {
            if (rawVuln.getId() % 2 == 0) {
                fail();
            }
        }
    }
}