/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author axoeec
 *
 */
@Slf4j
public abstract class AbstractCveParser {

	protected final String regexCVEID = "CVE-[0-9]+-[0-9]+";
	protected final String regexVersionInfo = "(?:(\\d+\\.(?:\\d+\\.)*\\d+))";
	protected final String regexAllCVERelatedContent = ".*(affect|attack|bypass|cve|execut|fix|flaw|permission|vulnerab|CVE|Mitigat|(?:(\\d+\\.(?:\\d+\\.)*\\d+))).*";
	protected final String regexDateFormat = "([a-zA-Z]+ [0-9]+, [0-9]+)";
	protected final String regexDateFormatNumeric = "[0-9]+[-/][0-9]+[-/][0-9]+";
	protected final String regexDateYearMonthDay = "\\d{4}-(0?[1-9]|1[012])-(0?[1-9]|[12][0-9]|3[01])*";
	protected final String regexDates = "(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*?\\s+\\d{1,2}(?:[a-z]{2})?(?:\\s+|,\\s*)\\d{4}\\b";
	protected final String regexChinese = "\\p{IsHan}";
	protected final DateFormat dateFormat_MMMddCommaYYYY = new SimpleDateFormat("MMM dd, yyyy", Locale.ENGLISH);
	protected final DateFormat dateFormat_MMMddYYYY = new SimpleDateFormat("MMM dd yyyy", Locale.ENGLISH);
	protected final DateFormat dateFormat_yyyy_MM_dd = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);

	protected String sourceDomainName = null;

	public abstract List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML);

	/**
	 * Get Dynamic HTML with Selenium
	 * JSoup only extracts static web pages
	 * @param url
	 * @return
	 */
	protected String grabDynamicHTML(String url, SeleniumDriver driver) {
		String html = driver.tryPageGet(url);
		// if (url.contains("mend.io"))
		// 	return (String) ((JavascriptExecutor) driver.getDriver()).executeScript("return document.getElementsByTagName('html')[0].innerHTML");
		return html;
	}

	/**
	 * get unique CVEs
	 *
	 * @param sCVEContentHTML
	 * @return
	 */
	protected Set<String> getCVEs(String sCVEContentHTML) {
		Set<String> uniqueCves = new HashSet<>();
		Pattern cvePattern = Pattern.compile(regexCVEID);
		Matcher cveMatcher = cvePattern.matcher(sCVEContentHTML);
		while (cveMatcher.find())
			uniqueCves.add(cveMatcher.group());

		return uniqueCves;
	}

	protected String getCVEID(String sCVEContentHTML) {
		String cve = "";
		Pattern cvePattern = Pattern.compile(regexCVEID);
		Matcher cveMatcher = cvePattern.matcher(sCVEContentHTML);
		if (cveMatcher.find())
			cve = cveMatcher.group();

		return cve;
	}

	protected String getCVEDate(String dateContentHTML) {
		String date = "";
		Pattern cvePattern = Pattern.compile(regexDates);
		Matcher cveMatcher = cvePattern.matcher(dateContentHTML);
		if (cveMatcher.find())
			date = cveMatcher.group();

		return date;
	}

	/**
	 * Check if HTML contains Chinese chars?
	 *
	 * @param sHTML
	 * @return
	 */
	protected boolean containsChineseChars(String sHTML) {
		Pattern cvePattern = Pattern.compile(regexChinese);
		Matcher cveMatcher = cvePattern.matcher(sHTML);
		return cveMatcher.find();
	}

	/**
	 * Helper function for extractDate and extractLastModifiedDate
	 * Find keyword in text, return a bounds to search for a date in
	 * text surrounding the location of the keyword
	 * @param text - text to search for dates
	 * @param keyword - keyword to search for in text
	 * @return array of substring bounds
	 */
	protected int[] getSubstringBounds(String text, String keyword) {
		// bounds to isolate date text for individual CVE ID's in bulletin
		final int DATE_BOUNDS = 40;
		int[] bounds = new int[2];
		int keywordIndex = text.toLowerCase().indexOf(keyword);
		if (keywordIndex == -1) return bounds;
		bounds[0] = keywordIndex;
		bounds[1] = Math.min(keywordIndex + DATE_BOUNDS, text.length());
		return bounds;
	}

	/**
	 * Search for relevant date keywords and attempt to
	 * extract a date from the text around it
	 * Fall through to grabbing any date in the text if no
	 * keywords/dates around keywords are found
	 * @param text - text to search for dates
	 * @return GenericDate object referencing relevant date from text
	 */
	protected GenericDate extractDate(String text) {
		// search for "Published" "Created" "Modified" "Updated" keywords, grab dates around it
		// check a subtext for a date based on these keywords
		GenericDate possibleDate = null;
		if (text.toLowerCase().contains("published")) {
			// grab date around published
			int[] bounds = getSubstringBounds(text, "published");
			possibleDate = new GenericDate(text.substring(bounds[0], bounds[1]));
		} else if (text.toLowerCase().contains("created")) {
			// grab date around created
			int[] bounds = getSubstringBounds(text, "created");
			possibleDate = new GenericDate(text.substring(bounds[0], bounds[1]));
		}
		if (possibleDate != null && possibleDate.getRawDate() != null)
			return possibleDate;
		// otherwise try to find any sort of date in the text (this might give back rogue dates in descriptions, etc...)
		return new GenericDate(text);
	}

	/**
	 * Search for last modified keywords in attempts to grab
	 * last modified date around it
	 * Fall through to grabbing any date in the text
	 * @param text - text to search for date
	 * @return GenericDate object referencing relevant date found in text
	 */
	protected GenericDate extractLastModifiedDate(String text) {
		// search for "Published" "Created" "Modified" "Updated" keywords, grab dates around it
		// check a subtext for a date based on these keywords
		GenericDate possibleDate = null;
		if (text.toLowerCase().contains("modified")) {
			// grab date around modified
			int[] bounds = getSubstringBounds(text, "modified");
			possibleDate = new GenericDate(text.substring(bounds[0], bounds[1]));
		} else if (text.toLowerCase().contains("updated")) {
			// grab date around updated
			int[] bounds = getSubstringBounds(text, "updated");
			possibleDate = new GenericDate(text.substring(bounds[0], bounds[1]));
		}
		if (possibleDate != null && possibleDate.getRawDate() != null)
			return possibleDate;
		// otherwise try to find any sort of date in the text (this might give back rogue dates in descriptions, etc...)
		return new GenericDate(text);
	}

	/**
	 * Extract platform version from txt
	 *
	 * @param description
	 * @return list of strings in format [product name] [version]
	 */
	protected List<String> getPlatformVersions(String description) {
		String version;
		Set<String> versions = new HashSet<>();

		Pattern pattern = Pattern.compile(regexVersionInfo);
		Matcher matcher;

		String[] sentences = description.split("\n|[.] ");

		List<Character> illegalChars = new ArrayList<>(Arrays.asList(':', ';', '*', ',', '.', '\\', '/', '=', '\''));

		for (String s : sentences) {
			matcher = pattern.matcher(s);
			while (matcher.find()) {
				version = matcher.group(0);
				if (version == null)
					continue;

				int beginIndex = s.lastIndexOf(version);

				int lastUppercase = -1;
				for (int i = beginIndex - 1; i >= 0; i--) {
					char currChar = s.charAt(i);
					if (illegalChars.contains(currChar))
						break;
					if (Character.isUpperCase(currChar))
						lastUppercase = i;

					// If this word didn't start with uppercase or if you are at the beginning of the
					// sentence, return substring
					if ((currChar == ' ' && (lastUppercase != i + 1 && i != beginIndex - 1)) || i == 0)
						break;

				}
				if (lastUppercase == -1)
					continue;

				versions.add(s.substring(lastUppercase, beginIndex + version.length()));
			}
		}
		return new ArrayList<>(versions);
	}


	/**
	 * * grab pdf file from given url, convert to string, and return
	 * @param pdfLink - online pdf link
	 * @return - String formatted version of the pdf file listed online
	 */
	protected String pdfToString(String pdfLink){
		String pdfText = "";
		try {
			URL url = new URL(pdfLink);
			HttpURLConnection httpcon = (HttpURLConnection) url.openConnection();
			httpcon.addRequestProperty("User-Agent", "Mozilla/4.0");
			InputStream file = httpcon.getInputStream();
			PDDocument pdf = PDDocument.load(file);
			pdfText = new PDFTextStripper().getText(pdf);
			pdf.close();
		} catch (IOException e) {
			log.error("", e);
		}
		return pdfText;
	}

	/**
	 * Generates an xPath expression to reference a Selenium
	 * WebElement using a given Jsoup Element as the starting point
	 * @param element The Jsoup Element to generate the xPath for
	 * @return The xPath expression as a String
	 */
	public static String jsoupToXpath(Element element) {
		// Initialize the XPath with the root element
		String xpath = "/";
		// Initialize a list to store the XPath components
		List<String> components = new ArrayList<>();

		// Determine the child element to start the traversal from
		Element child = element.tagName().isEmpty() ? element.parent() : element;

		// Traverse up the DOM tree until the root element is reached
		while (child.parent() != null){
			// Get the parent element
			Element parent = child.parent();
			// Get the siblings of the child element
			Elements siblings = parent.children();
			// Initialize a variable to store the XPath component for the child element
			String componentToAdd = null;

			// If the child element is the only one of its kind among its siblings, use its tag name as the component
			if (siblings.size() == 1) {
				componentToAdd = child.tagName();
			} else {
				// If there are multiple siblings with the same tag name, use an index to differentiate between them
				int x = 1;
				for(Element sibling: siblings){
					if (child.tagName().equals(sibling.tagName())){
						if (child == sibling){
							break;
						} else {
							x++;
						}
					}
				}
				componentToAdd = String.format("%s[%d]", child.tagName(), x);
			}
			// Add the XPath component for the child element to the list of components
			components.add(componentToAdd);
			// Move up the DOM tree to the parent element
			child = parent;
		}

		// Reverse the list of components to get the XPath in the correct order
		List<String> reversedComponents = new ArrayList<>();
		for (int i = components.size()-1; i > 0; i--){
			reversedComponents.add(components.get(i));
		}
		// Join the reversed components into a single XPath string
		xpath = xpath + String.join("/", reversedComponents);

		// Return the final XPath
		return xpath;
	}

}
