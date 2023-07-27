package edu.rit.se.nvip.process;

public class ProcessorFactory {

    public static final String SIMPLE = "SIMPLE";
    public static final String NVDCOMP = "NVDCOMP";
    public static final String MITRECOMP = "MITRECOMP";

    public static Processor createProcessor(String type) {

        switch (type) {
            case SIMPLE:
                return new SimpleProcessor();
            case NVDCOMP:
                return new NVDCompareProcess();
            case MITRECOMP:
                return new MITRECompareProcess();
            default:
                return new SimpleProcessor();
        }

    }
}
