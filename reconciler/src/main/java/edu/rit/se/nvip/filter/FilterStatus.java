package edu.rit.se.nvip.filter;

import java.util.Arrays;

public enum FilterStatus {
    NEW(0),
    UNEVALUATED(1),
    PASSED(2),
    FAILED(3);
    public final int value;
    FilterStatus(int value) {
        this.value = value;
    }
    public static FilterStatus get(int value) {
        return Arrays.stream(FilterStatus.values()).filter(v -> v.value == value).findFirst().orElse(FAILED);
    }
}
