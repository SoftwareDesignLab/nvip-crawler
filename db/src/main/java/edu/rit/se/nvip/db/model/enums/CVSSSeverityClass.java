package edu.rit.se.nvip.db.model.enums;

public enum CVSSSeverityClass {
    HIGH(1),
    MEDIUM(2),
    NA(3),
    CRITICAL(4),
    LOW(5);
    public final int cvssSeverityId;
    CVSSSeverityClass(int cvssSeverityId) {
        this.cvssSeverityId = cvssSeverityId;
    }

    public static CVSSSeverityClass getCVSSSeverityByScore(double cvssScore){
        if (cvssScore < 4) return LOW;
        if (cvssScore <= 6.5) return MEDIUM;
        if (cvssScore < 9) return HIGH;
        return CRITICAL;
    }
}
