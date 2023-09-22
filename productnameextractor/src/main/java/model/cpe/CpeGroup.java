package model.cpe;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
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

import lombok.Data;
import opennlp.tools.tokenize.WhitespaceTokenizer;

import java.util.HashMap;

/** 
 * This class is for CPE groups
 * @author Igor Khokhlov
 *
 */
@Data
public class CpeGroup {
	private final String vendor;
	private final String product;
	private final String groupID;
	private String commonTitle;
	private final HashMap<String, CpeEntry> versions;

	public CpeGroup(String vendor, String product) {
		super();
		this.vendor = vendor;
		this.product = product;
		this.groupID = vendor+":"+product;
		this.versions = new HashMap<>();
	}

	public CpeGroup(String vendor, String product, String commonTitle, HashMap<String, CpeEntry> versions) {
		super();
		this.vendor = vendor;
		this.product = product;
		this.groupID = vendor+":"+product;
		this.commonTitle = commonTitle;
		this.versions = versions;
	}
	
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
}
