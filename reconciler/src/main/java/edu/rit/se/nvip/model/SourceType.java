package edu.rit.se.nvip.model;

import java.util.Arrays;

public enum SourceType {
    CNA("cna", 1),
    SA("security_advisory", 1),
    THIRD_PARTY("third_party", 0),
    BUG_BOUNTY("bug_bounty", 0),
    USER("user", 2),
    OTHER("other", 0);

    public final String type;
    public static final int MAX_PRIORITY = 2;
    public final int priority;
    SourceType(String label, int priority) {
        this.type = label;
        this.priority = priority;
    }
    public String getType() {
        return this.type;
    }
    public static SourceType get(String sourceType) {
        if (sourceType == null) {
            return OTHER;
        }
        if (sourceType.startsWith("usersource")) {
            return USER;
        }
        return Arrays.stream(SourceType.values()).filter(st -> st.type.equals(sourceType)).findFirst().orElse(OTHER);
    }
}
