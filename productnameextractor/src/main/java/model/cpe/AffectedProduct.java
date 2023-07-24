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

/**
 * 
 * @author axoeec
 *
 */
public class AffectedProduct {

	private final int id;
	private String cveId;
	private final String cpe;
	private String productName;
	private String releaseDate;
	private String version;
	private String vendor;
	private String purl;
	private String swid;

	public AffectedProduct(int id, String cveId, String cpe, String releaseDate, String version) {
		this.id = id;
		this.cveId = cveId;
		this.cpe = cpe;
		this.releaseDate = releaseDate;
		this.version = version;
	}

	public AffectedProduct(int id, String cveId, String cpe, String productName, String releaseDate, String version, String vendor) {
		this(id, cveId, cpe, releaseDate, version);
		this.productName = productName;
		this.vendor = vendor;
		generatePURL();
		generateSWID();
	}

	public AffectedProduct(String cpe, String releaseDate, String version) {
		this.id = 0;
		this.cveId = null;
		this.cpe = cpe;
		this.releaseDate = releaseDate;
		this.version = version;
	}

	public AffectedProduct(AffectedProduct a) {
		this.id = a.id;
		this.cveId = a.cveId;
		this.cpe = a.cpe;
		this.releaseDate = a.releaseDate;
		this.version = a.version;
		this.vendor = a.vendor;
		this.purl = a.purl;
		this.swid = a.swid;
	}

	public int getId() {
		return id;
	}

	public String getCveId() {
		return cveId;
	}

	public String getCpe() {
		return cpe;
	}

	public String getProductName() {
		return productName;
	}

	public String getReleaseDate() {
		return releaseDate;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}
	public String getVendor() {
		return vendor;
	}

	public String getPURL(){
		return purl;
	}

	public String getSWID(){
		return swid;
	}

	public void setVendor(String vendor) {
		this.vendor = vendor;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public void setReleaseDate(String releaseDate) {
		this.releaseDate = releaseDate;
	}

	/**
	* Generates PURL using vendor, product name and version
	* Format: scheme:type/namespace/name@version?qualifiers#subpath
	* Where scheme is "pkg", vendor is the type, product name is the name and version is the version
	*
	*/
	private void generatePURL(){
		String result = "pkg:";
		StringBuilder purlBuilder = new StringBuilder(result);
		purlBuilder.append(vendor).append("/").append(productName);
		if(!version.equals("*") && !version.equals("")){
			purlBuilder.append("@").append(version);
		}
		purl = purlBuilder.toString();
	}

	/**
	 * Generate SWID using product name
	 * Scheme: swid:productname@version
	 */
	private void generateSWID(){
		//match the scheme
		String result = "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\" ";
		StringBuilder swidBuilder = new StringBuilder(result);
		//match the name
		swidBuilder.append("name=\"").append(productName).append("\" ");
		//match the tagId, remove space from productName, don't add . if version is ""
		if(!version.equals("*") && !version.equals("")){
			swidBuilder.append("tagId=\"").append(vendor).append(".").append(productName.replaceAll("\\s+","")).append(".").append(version).append("\" ");
			swidBuilder.append("version=\"").append(version).append("\">");
		}else{
			swidBuilder.append("tagId=\"").append(vendor).append(".").append(productName.replaceAll("\\s+","")).append(version).append("\" ");
			swidBuilder.append("version=\"\">");
		}
		//match the entity
		swidBuilder.append("<Entity name=\"").append(vendor).append("\" regid=\"").append("com.").append(vendor).append("\">");
		//match the meta
		swidBuilder.append("<Meta product=\"").append(productName).append("\" colloquialVersion=\"").append(version).append("\"/>");
		//match the payload
		swidBuilder.append("<Payload>");
		swidBuilder.append("<File name=\"").append(productName.replaceAll("\\s+","")).append(".exe\" size=\"532712\" SHA256:hash=\"a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a\"/>");
		swidBuilder.append("</Payload>");
		swidBuilder.append("</SoftwareIdentity>");
		swid = swidBuilder.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AffectedProduct))
			return false;
		AffectedProduct other = (AffectedProduct) obj;
		return other.cveId.equals(this.cveId) && other.cpe.equals(this.cpe);

	}

	@Override
	public String toString() {
		return "AffectedProduct [cveId=" + cveId + ", cpe=" + cpe + ", releaseDate=" + releaseDate + ", version=" + version + "]";
	}

}
