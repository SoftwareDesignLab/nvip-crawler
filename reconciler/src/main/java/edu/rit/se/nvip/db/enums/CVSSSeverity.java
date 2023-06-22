package edu.rit.se.nvip.db.enums;

public enum CVSSSeverity {
    HIGH(1),
    MEDIUM(2),
    NA(3),
    CRITICAL(4),
    LOW(5);

    private final int cvssSeverityId;

    CVSSSeverity(int cvssSeverityId) {
        this.cvssSeverityId = cvssSeverityId;
    }

    public int getCvssSeverityId() {
        return cvssSeverityId;
    }
}
