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
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.SeleniumDriver;

/**
 * 
 * @author axoeec
 *
 */
public class CveParserFactory {

	/**
	 * return the parser for this Url
	 */
	public AbstractCveParser createParser(String sPageUrl, SeleniumDriver driver) {
		if (sPageUrl == null) {
			return new NullParser();
		}

		if (sPageUrl.contains("https://github.com/advisories/") || sPageUrl.contains("github.com/advisories"))
			return new GitHubAdvisoryParser(driver);

		if (sPageUrl.contains("tenable.com") && !sPageUrl.contains("blog")) {
			if (sPageUrl.contains("security"))
				return new TenableSecurityParser();
			else
				return new TenableCveParser();
		}
		else if (sPageUrl.contains("exploit-db") && sPageUrl.contains("exploits"))
			return new ExploitDBParser();
		else if (sPageUrl.contains("kb.cert"))
			return new KbCertCveParser();
		else if (sPageUrl.contains("packetstorm"))
			return new PacketStormParser();
		else if (sPageUrl.contains("talosintelligence"))
			return new TalosIntelligenceParser();

		// all gentoo pages in this if statement
		else if (sPageUrl.contains("gentoo")) {
			if (sPageUrl.contains("bugs"))
				return new BugsGentooParser();
			else if (sPageUrl.contains("security"))
				return new SecurityGentooParser();
			else if (sPageUrl.contains("news"))
				return new NullParser();
			else if (sPageUrl.contains("blogs"))
				return new NullParser();
			else
				return new GenericCveParser("nat_available", driver);
		}
		else if (sPageUrl.contains("vmware") && sPageUrl.contains("advisories"))
			return new VMWareAdvisoriesParser();
		else if (sPageUrl.contains("bugzilla"))
			return new BugzillaParser();
		else if (sPageUrl.contains("anquanke"))
			return new AnquankeParser();
		else if (sPageUrl.contains("seclists"))
			return new SeclistsParser();
		else if (sPageUrl.contains("redhat") && sPageUrl.contains("security")) {
			if (sPageUrl.contains("security-updates"))
				return new SecurityRedHatParser();
			else if (sPageUrl.contains("cve"))
				return new RedHatParser();
		}
		else if (sPageUrl.contains("bosch") && sPageUrl.contains("security-advisories"))
			return new BoschSecurityParser();
		else if (sPageUrl.contains("cloud.google") && sPageUrl.contains("bulletins"))
			return new GoogleCloudParser();
		else if (sPageUrl.contains("atlassian"))
			return new AtlassianParser();
		else if (sPageUrl.contains("mend.io"))
			return new MendParser();
		else if (sPageUrl.contains("autodesk"))
			return new AutodeskParser();
		else if (sPageUrl.contains("jenkins.io"))
			return new JenkinsParser();
		else if (sPageUrl.contains("coresecurity"))
			return new CoreParser();
		else if (sPageUrl.contains("mozilla"))
			return new MozillaParser();
		else if (sPageUrl.contains("intel"))
			return new IntelParser();
		else if (sPageUrl.contains("msrc"))
			return new MicrosoftParser();
		else if (sPageUrl.contains("trustwave"))
			return new TrustWaveParser();
		else if (sPageUrl.contains("zerodayinitiative"))
			return new TrendMicroParser("zerodayinitiative");
		else if (sPageUrl.contains("tibco"))
			return new TibcoParser();
		else if (sPageUrl.contains("android"))
			return new AndroidParser();
		else if (sPageUrl.contains("huntr"))
			return new HuntrParser();
		else if (sPageUrl.contains("jvn"))
			return new JVNParser();
		else if (sPageUrl.contains("curl"))
			return new CurlParser();
		else if (sPageUrl.contains("snyk.io"))
			return new SnykParser();
		else if (sPageUrl.contains("acronis"))
			return new AcronisParser();
		else if (sPageUrl.contains("veritas"))
			return new VeritasParser();
		else if (sPageUrl.contains("adobe"))
			return new AdobeParser();
		else if (sPageUrl.contains("aliasrobotics"))
			return new AliasRoboParser();
		else if (sPageUrl.contains("amperecomputing.com/products/product-security"))
			return new AmpereRootParser();
		else if (sPageUrl.contains("arubanetworks"))
			return new ArubaParser();
		else if (sPageUrl.contains("cybersecurityworks"))
			return new ZeroDaysParser();
		else if (sPageUrl.contains("dragos"))
			return new DragosParser();
		else if (sPageUrl.contains("cyberark"))
			return new CyberArkRootParser();
		else if (sPageUrl.contains("dotcms"))
			return new DotCMSParser();
		else if (sPageUrl.contains("pandorafms"))
			return new PandoraFMSRootParser();
		else if (sPageUrl.contains("libreoffice"))
			return new LibreOfficeParser();
		else if (sPageUrl.contains("samba.org"))
			return new SambaParser();
		else if (sPageUrl.contains("asustor"))
			return new AsustorParser();
		else if (sPageUrl.contains("abb.com"))
			return new ABBParser();
		else if (sPageUrl.contains("eaton"))
			return new EatonParser();
		else if (sPageUrl.contains("arista"))
			return new AristaParser();
		else if (sPageUrl.contains("nvidia"))
			return new ParseTable("nvidia", driver);


		// sources that you want to ignore
		// we ignore mitre/nvd because we pull their up to date CVEs from Github
		else if (sPageUrl.contains("mitre.org") || sPageUrl.contains("nist.gov"))
			return new NullParser();

		return new GenericCveParser("nat_available", driver);
	}

}
