package edu.rit.se.nvip.characterizer.enums;

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

    public int getCvssSeverityId() {
        return cvssSeverityId;
    }

    public static CVSSSeverityClass getCVSSSeverityById(int cvssSeverityId){
        for(CVSSSeverityClass cvss : CVSSSeverityClass.values()){
            if (cvssSeverityId == cvss.getCvssSeverityId()){
                return cvss;
            }
        }
        return null;
    }

    public static CVSSSeverityClass getCVSSSeverityByScore(double cvssScore){
        if (cvssScore < 4) return LOW;
        if (cvssScore <= 6.5) return MEDIUM;
        if (cvssScore < 9) return HIGH;
        return CRITICAL;
    }
}
