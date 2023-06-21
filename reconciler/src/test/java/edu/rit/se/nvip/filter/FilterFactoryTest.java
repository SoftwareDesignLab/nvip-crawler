package edu.rit.se.nvip.filter;

import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertTrue;

class FilterFactoryTest {

    @Test
    void createSimpleFilter() {
        Filter filter = FilterFactory.createFilter("SIMPLE");
        assertTrue(filter instanceof SimpleFilter);
    }

    @Test
    void createDefaultFilter() {
        Filter filter = FilterFactory.createFilter("UNRECOGNIZED");
        assertTrue(filter instanceof SimpleFilter);
    }
}