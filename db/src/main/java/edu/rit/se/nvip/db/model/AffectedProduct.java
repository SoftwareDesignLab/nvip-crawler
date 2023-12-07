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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

/**
 *
 * Class to represent a product that is affected by a CVE.
 *
 * @author axoeec
 * @author Paul Vickers
 * @author Richard Sawh
 *
 */
@EqualsAndHashCode
public class AffectedProduct {
	@Getter @Setter	String cveId;
	@Getter private final String cpe;
	@Getter private String productName;
	@Getter @Setter private String version;
	@Getter @Setter private String vendor;
	@Getter private String purl;
	private String swid;

	/**
	 * Default constructor for an affectedProduct
	 *
	 * @param cveId CVE that affects the product
	 * @param cpe CPE for the product
	 * @param version version of the product
	 */
	public AffectedProduct(String cveId, String cpe, String version) {
		this.cveId = cveId;
		this.cpe = cpe;
		this.version = version;
	}

	/**
	 * Same as above but includes vendor and product name. Because of this, generatePURL() and generateSWID() are called
	 * as they can only be built if vendor and product name are known.
	 *
	 * @param vendor vendor of the product
	 * @param productName name of the product
	 */
	public AffectedProduct(String cveId, String cpe, String productName, String version, String vendor) {
		this(cveId, cpe, version);
		this.productName = productName;
		this.vendor = vendor;
		generatePURL();
		generateSWID();
	}

	// Generate with just cpe, releaseDate and version
	public AffectedProduct(String cpe, String version) {
		this.cveId = null;
		this.cpe = cpe;
		this.version = version;
	}

	// Creates a copy of another affectedProduct
	public AffectedProduct(AffectedProduct a) {
		this.cveId = a.cveId;
		this.productName = a.productName;
		this.cpe = a.cpe;
		this.version = a.version;
		this.vendor = a.vendor;
		this.purl = a.purl;
		this.swid = a.swid;
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
	 * Generate SWID for the affectedproduct
	 * Format: swid:productname@version
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

	public String getSWID(){
		return this.swid;
	}

	public String getPURL(){
		return this.purl;
	}

	@Override
	public String toString() {
		return "AffectedProduct [cveId=" + cveId + ", cpe=" + cpe + ", version=" + version + "]";
	}

}
