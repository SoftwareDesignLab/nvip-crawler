package edu.rit.se.nvip.productnameextractor;

import main.java.SWIDLookUp;
import org.junit.Before;
import org.junit.Test;
import main.java.ProductItem;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class SWIDLookUpTest {
    private SWIDLookUp swidLookUp;

    @Before
    public void setUp() {
        swidLookUp = SWIDLookUp.getInstance();
        swidLookUp.addSWIDEntry(new ProductItem("Product A"));
        swidLookUp.addSWIDEntry(new ProductItem("Product B"));
    }

    @Test
    public void testGetSWIDEntries() {
        List<SWIDLookUp.SWIDEntry> entriesA = swidLookUp.getSWIDEntries("Product A");
        assertEquals(1, entriesA.size());
        assertEquals("Product A", entriesA.get(0).getProductName());

        List<SWIDLookUp.SWIDEntry> entriesB = swidLookUp.getSWIDEntries("Product B");
        assertEquals(1, entriesB.size());
        assertEquals("Product B", entriesB.get(0).getProductName());
    }

    @Test
    public void testGetSWID() {
        String swidA = swidLookUp.getSWID("Product A");
        assertEquals("swid:Product_A:1.0", swidA);

        String swidB = swidLookUp.getSWID("Product B");
        assertEquals("swid:Product_B:1.0", swidB);
    }
}