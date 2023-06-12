package process;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProcessorFactoryTest {

    @Test
    void createSimpleProcessor() {
        Processor p = ProcessorFactory.createProcessor("SIMPLE");
        assertTrue(p instanceof SimpleProcessor);
    }

    @Test
    void createDefaultProcessor() {
        Processor p = ProcessorFactory.createProcessor("UNRECOGNIZED");
        assertTrue(p instanceof SimpleProcessor);
    }
}