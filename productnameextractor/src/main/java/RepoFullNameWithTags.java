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

import java.io.Serializable;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 *  contains information about a repository
 * 
 * @author Igor Khokhlov
 *
 */

public class RepoFullNameWithTags implements Serializable{

	private String url;
	private final String cpeID;
	private ArrayList<RepoTag> tags;

	public RepoFullNameWithTags(JSONObject repo) {
		super();
		this.url = repo.getString("url");
		this.cpeID = repo.getString("cpe_i_d");

		JSONArray tagsArray = repo.getJSONArray("tags");
		if (tagsArray != null && tagsArray.length()>0) {
			tags = parseTags(tagsArray);
		}
		else {
			tags = new ArrayList<>();
		}
	}
	
	static public ArrayList<RepoTag> parseTags(JSONArray tagsArray){
		ArrayList<RepoTag> tags = new ArrayList<>();
		
		for(int i=0; i<tagsArray.length(); i++) {
			tags.add(new RepoTag(tagsArray.getJSONObject(i)));
		}
		
		return tags;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}


	public ArrayList<RepoTag> getTags() {
		return tags;
	}

	public void setTags(ArrayList<RepoTag> tags) {
		this.tags = tags;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((cpeID == null) ? 0 : cpeID.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RepoFullNameWithTags other = (RepoFullNameWithTags) obj;
		if (cpeID == null) {
			return other.cpeID == null;
		} else return cpeID.equals(other.cpeID);
	}
}
