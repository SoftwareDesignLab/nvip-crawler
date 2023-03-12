package edu.rit.se.nvip.mitre.capec;

public class CapecRelationship {

    private String nature;
    private CapecRelationshipType type;
    private String capecID;
    private String capecName;

    public CapecRelationship(String nature, String type, String id, String name) {
        this.nature = nature;
        switch(type) {
            case "Meta Attack Pattern":
                this.type = CapecRelationshipType.META;
                break;
            case "Detailed Attack Pattern":
                this.type = CapecRelationshipType.DETAILED;
                break;
            case "Standard Attack Pattern":
            default:
                this.type = CapecRelationshipType.STANDARD;
        }
        this.capecID = id;
        this.capecName = name;
    }
}
