package edu.rit.se.nvip.process;

import org.junit.jupiter.api.Test;

import java.util.HashSet;

class SimpleProcessorTest {

    @Test
    void process() {
        Processor p = new SimpleProcessor();
        p.process(new HashSet<>());
        // that's all!, just need not errors to be thrown
    }

}