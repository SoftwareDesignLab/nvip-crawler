package mitre.capec;

public enum CapecType {

    /**
     * Standard Attack Pattern -
     * A standard level attack pattern in CAPEC is focused on a
     * specific methodology or technique used in an attack. It is often seen as a singular
     * piece of a fully executed attack. A standard attack pattern is meant to provide sufficient
     * details to understand the specific technique and how it attempts to accomplish a
     * desired goal. A standard level attack pattern is a specific type of a more abstract meta level attack pattern.
     */
    STANDARD,

    /**
     * Detailed Attack Pattern -
     * A detailed level attack pattern in CAPEC provides a low level
     * of detail, typically leveraging a specific technique and targeting a specific technology,
     * and expresses a complete execution flow. Detailed attack patterns are more specific than
     * meta attack patterns and standard attack patterns and often require a specific protection
     * mechanism to mitigate actual attacks. A detailed level attack pattern often will leverage a
     * number of different standard level attack patterns chained together to accomplish a goal.
     */
    DETAILED,

    /**
     * Meta Attack Pattern -
     * A meta level attack pattern in CAPEC is a decidedly abstract
     * characterization of a specific methodology or technique used in an attack. A meta attack
     * pattern is often void of a specific technology or implementation and is meant to provide
     * an understanding of a high level approach. A meta level attack pattern is a generalization
     * of related group of standard level attack patterns. Meta level attack patterns are particularly
     * useful for architecture and design level threat modeling exercises.
     */
    META,

}
