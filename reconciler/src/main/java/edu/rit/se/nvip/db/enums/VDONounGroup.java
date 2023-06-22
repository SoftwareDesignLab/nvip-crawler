package edu.rit.se.nvip.db.enums;

public enum VDONounGroup {
    IMPACT_METHOD(1, "ImpactMethod", "Impact Method"),
    CONTEXT(2, "Context", "Context"),
    MITIGATION(3, "Mitigation", "Mitigation"),
    ATTACK_THEATER(4, "AttackTheater", "Attack Theater"),
    LOGICAL_IMPACT(5, "LogicalImpact", "Logical Impact");

    private int vdoNounGroupId;
    private String vdoNounGroupName;
    private String vdoNameForUI;

    VDONounGroup(int vdoNounGroupId, String vdoNounGroupName, String vdoNameForUI) {
        this.vdoNounGroupId = vdoNounGroupId;
        this.vdoNounGroupName = vdoNounGroupName;
        this.vdoNameForUI = vdoNameForUI;
    }

    public int getVdoNounGroupId() {
        return vdoNounGroupId;
    }

    public String getVdoNounGroupName() {
        return vdoNounGroupName;
    }

    public String getVdoNameForUI() {
        return vdoNameForUI;
    }
}