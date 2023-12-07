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

package edu.rit.se.nvip.db.model;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import opennlp.tools.tokenize.WhitespaceTokenizer;

import java.util.HashMap;

/** 
 * This class is for CPE groups
 * @author Igor Khokhlov
 *
 */
@Data
@RequiredArgsConstructor
@AllArgsConstructor
public class CpeGroup {
	private final String vendor;
	private final String product;
	@Getter private String commonTitle;
	@Getter	private HashMap<String, CpeEntry> versions = new HashMap<>();
	
	/**
	 * Add CPE entry (version) to the CPE group
	 * 
	 * @param version CPE entry (version) to add
	 */	
	public void addVersion(CpeEntry version) {
		
		versions.put(version.getVersion(), version);
		
		if (commonTitle == null || commonTitle.length()==0) {
			commonTitle = version.getTitle();
		}
		else {
			//Split titles into arrays of strings
			String[] existingTitleWords = WhitespaceTokenizer.INSTANCE.tokenize(commonTitle);
			String[] entryTitleWords = WhitespaceTokenizer.INSTANCE.tokenize(version.getTitle());
			
			//Common title for all entries
			StringBuilder newCommonTitle= new StringBuilder();
			for (int i=0; i<existingTitleWords.length && i<entryTitleWords.length; i++) {
				if(existingTitleWords[i].equalsIgnoreCase(entryTitleWords[i])) {
					newCommonTitle.append(existingTitleWords[i]).append(" ");
				}
			}
			
			//Keep only those words that are present in all entries' title
			if (newCommonTitle.length()>0) {
				commonTitle=newCommonTitle.substring(0, newCommonTitle.length()-1);
			}
		}
	}

	public int getVersionsCount() { return this.versions.size(); }

	public String getGroupID(){
		return String.format("%s:%s", vendor, product);
	}
}
