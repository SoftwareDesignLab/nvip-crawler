package edu.rit.se.nvip.process;

public class ProcessorFactory {

    public static final String SIMPLE = "SIMPLE";


    public static Processor createProcessor(String type) {

        switch (type) {
            case SIMPLE:
                return new SimpleProcessor();
            default:
                return new SimpleProcessor();
        }

    }
}
