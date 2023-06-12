package filter;

public class FilterFactory {

    public static final String SIMPLE = "SIMPLE";

    public static Filter createFilter(String type) {
        switch (type) {
            case SIMPLE:
                return new SimpleFilter();
            default:
                return new SimpleFilter();
        }
    }
}
