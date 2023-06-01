package edu.rit.se.nvip.productnameextractor;

import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class SWIDLookUpTest {

    private SWIDLookUp swidLookUp;

    @Before
    public void setUp() {
        swidLookUp = SWIDLookUp.getInstance();
        swidLookUp.addSWIDEntry("Product A", "SWID_A1");
        swidLookUp.addSWIDEntry("Product A", "SWID_A2");
        swidLookUp.addSWIDEntry("Product B", "SWID_B1");
        swidLookUp.addSWIDEntry("Product C", "SWID_C1");
    }

    @Test
    public void testGetSWIDEntries() {
        List<SWIDLookUp.SWIDEntry> entriesA = swidLookUp.getSWIDEntries("Product A");
        assertEquals(2, entriesA.size());
        assertEquals("SWID_A1", entriesA.get(0).getSWID());
        assertEquals("SWID_A2", entriesA.get(1).getSWID());

        List<SWIDLookUp.SWIDEntry> entriesB = swidLookUp.getSWIDEntries("Product B");
        assertEquals(1, entriesB.size());
        assertEquals("SWID_B1", entriesB.get(0).getSWID());

        List<SWIDLookUp.SWIDEntry> entriesC = swidLookUp.getSWIDEntries("Product C");
        assertEquals(1, entriesC.size());
        assertEquals("SWID_C1", entriesC.get(0).getSWID());
    }

    @Test
    public void testGetSWID() {
        String swidA = swidLookUp.getSWID("Product A");
        assertEquals("SWID_A1", swidA);

        String swidB = swidLookUp.getSWID("Product B");
        assertEquals("SWID_B1", swidB);

        String swidC = swidLookUp.getSWID("Product C");
        assertEquals("SWID_C1", swidC);

    }
}