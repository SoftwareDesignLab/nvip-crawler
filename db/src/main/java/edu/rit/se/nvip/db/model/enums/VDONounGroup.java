package edu.rit.se.nvip.db.model.enums;

public enum VDONounGroup{
    IMPACT_METHOD(1, "ImpactMethod", "Impact Method"),
    CONTEXT(2, "Context", "Context"),
    MITIGATION(3, "Mitigation", "Mitigation"),
    ATTACK_THEATER(4, "AttackTheater", "Attack Theater"),
    LOGICAL_IMPACT(5, "LogicalImpact", "Logical Impact");

    public int vdoNounGroupId;
    public String vdoNounGroupName;
    public String vdoNameForUI;

    VDONounGroup(int vdoNounGroupId, String vdoNounGroupName, String vdoNameForUI) {
        this.vdoNounGroupId = vdoNounGroupId;
        this.vdoNounGroupName = vdoNounGroupName;
        this.vdoNameForUI = vdoNameForUI;
    }

    public static VDONounGroup getVdoNounGroup(String vdoNounGroupName){
        for(VDONounGroup vdo : VDONounGroup.values()){
            if (vdoNounGroupName.equals(vdo.vdoNounGroupName)){
                return vdo;
            }
        }
        return null;
    }

}
