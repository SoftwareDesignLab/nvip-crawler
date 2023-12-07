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
