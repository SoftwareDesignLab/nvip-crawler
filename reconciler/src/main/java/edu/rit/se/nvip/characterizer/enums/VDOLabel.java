/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

package edu.rit.se.nvip.characterizer.enums;

public enum VDOLabel {
    TRUST_FAILURE(1, "Trust Failure", "Trust Failure", VDONounGroup.IMPACT_METHOD),
    MAN_IN_THE_MIDDLE(2, "Man-in-the-Middle", "Man-in-the-Middle", VDONounGroup.IMPACT_METHOD),
    CHANNEL(3, "Channel", "Channel", VDONounGroup.CONTEXT),
    AUTHENTICATION_BYPASS(4, "Authentication Bypass", "Authentication Bypass", VDONounGroup.IMPACT_METHOD),
    PHYSICAL_HARDWARE(5, "Physical Hardware", "Physical Hardware", VDONounGroup.CONTEXT),
    APPLICATION(6, "Application", "Application", VDONounGroup.CONTEXT),
    HOST_OS(7, "Host OS", "Host OS", VDONounGroup.CONTEXT),
    FIRMWARE(8, "Firmware", "Firmware", VDONounGroup.CONTEXT),
    CODE_EXECUTION(9, "Code Execution", "Code Execution", VDONounGroup.IMPACT_METHOD),
    CONTEXT_ESCAPE(10, "Context Escape", "Context Escape", VDONounGroup.IMPACT_METHOD),
    GUEST_OS(11, "Guest OS", "Guest OS", VDONounGroup.CONTEXT),
    HYPERVISOR(12, "Hypervisor", "Hypervisor", VDONounGroup.CONTEXT),
    SANDBOXED(13, "Sandboxed", "Sandboxed", VDONounGroup.MITIGATION),
    PHYSICAL_SECURITY(14, "Physical Security", "Physical Security", VDONounGroup.MITIGATION),
    ASLR(15, "ASLR", "ASLR", VDONounGroup.MITIGATION),
    LIMITED_RMT(16, "Limited Rmt", "Limited Rmt", VDONounGroup.ATTACK_THEATER),
    LOCAL(17, "Local", "Local", VDONounGroup.ATTACK_THEATER),
    READ(18, "Read", "Read", VDONounGroup.LOGICAL_IMPACT),
    RESOURCE_REMOVAL(19, "Resource Removal", "Resource Removal", VDONounGroup.LOGICAL_IMPACT),
    HPKP_HSTS(20, "HPKP/HSTS", "HPKP/HSTS", VDONounGroup.MITIGATION),
    MULTIFACTOR_AUTHENTICATION(21, "MultiFactor Authentication", "MultiFactor Authentication", VDONounGroup.MITIGATION),
    REMOTE(22, "Remote", "Remote", VDONounGroup.ATTACK_THEATER),
    WRITE(23, "Write", "Write", VDONounGroup.LOGICAL_IMPACT),
    INDIRECT_DISCLOSURE(24, "Indirect Disclosure", "Indirect Disclosure", VDONounGroup.LOGICAL_IMPACT),
    SERVICE_INTERRUPT(25, "Service Interrupt", "Service Interrupt", VDONounGroup.LOGICAL_IMPACT),
    PRIVILEGE_ESCALATION(26, "Privilege Escalation", "Privilege Escalation", VDONounGroup.LOGICAL_IMPACT),
    PHYSICAL(27, "Physical", "Physical", VDONounGroup.ATTACK_THEATER);

    public int vdoLabelId;
    public String vdoLabelName;
    public String vdoLabelForUI;
    public VDONounGroup vdoNounGroup;

    VDOLabel(int vdoLabelId, String vdoLabelName, String vdoLabelForUI, VDONounGroup vdoNounGroup) {
        this.vdoLabelId = vdoLabelId;
        this.vdoLabelName = vdoLabelName;
        this.vdoLabelForUI = vdoLabelForUI;
        this.vdoNounGroup = vdoNounGroup;
    }
    public static VDOLabel getVdoLabel(String vdoLabelName){
        for (VDOLabel label : VDOLabel.values()){
            if (label.vdoLabelName.equals(vdoLabelName)){
                return label;
            }
        }
        return null;
    }
}
