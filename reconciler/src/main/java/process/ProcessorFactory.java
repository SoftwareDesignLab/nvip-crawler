package process;

public class ProcessorFactory {

    public static final String SIMPLE = "SIMPLE";
    public static final String NVDCOMP = "NVDCOMP";

    public static Processor createProcessor(String type) {

        switch (type) {
            case SIMPLE:
                return new SimpleProcessor();
            case NVDCOMP:
                return new NVDCompareProcess();
            default:
                return new SimpleProcessor();
        }

    }
}
