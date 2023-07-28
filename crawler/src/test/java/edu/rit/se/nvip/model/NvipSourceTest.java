package edu.rit.se.nvip.model;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for NvipSource Model
 */
public class NvipSourceTest {
    @Test
    public void testNvipSource() {
        NvipSource obj = new NvipSource("url", "desc", 0);

        assertEquals(obj.getUrl(), "url");
        assertEquals(obj.getDescription(), "desc");
        assertEquals(obj.getHttpStatus(), 0);

        obj.setDescription("new_desc");
        obj.setSourceId(1);

        assertEquals(obj.getDescription(), "new_desc");
        assertEquals(obj.getSourceId(), 1);
    }

    @Test
    public void testNvipSourceToString() {
        NvipSource obj = new NvipSource("url", "desc", 0);
        String ref = 0 + ": " + "url";
        assertEquals(obj.toString(), ref);
    }
}