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
package crawler.htmlparser;

import io.github.bonigarcia.wdm.WebDriverManager;
import model.RawVulnerability;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author axoeec
 *
 */
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

	protected static volatile WebDriver driver = null;

	public abstract List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML);

	public static WebDriver startDynamicWebDriver() {
		System.setProperty("webdriver.chrome.silentOutput", "true");
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless","--user-agent=Mozilla/5.0");
		options.addArguments("--remote-allow-origins=*");
		options.addArguments("--enable-javascript");
		WebDriverManager.chromedriver().setup();
		ChromeDriverService chromeDriverService = new ChromeDriverService.Builder().build();
		return new ChromeDriver(chromeDriverService, options);
	}

	/**
	 * Get Dynamic HTML with Selenium
	 * JSoup only extracts static web pages
	 * @param url
	 * @return
	 */
	protected String grabDynamicHTML(String url) {

		// null in unit tests for now
		if (driver == null)
			driver = startDynamicWebDriver();
		while(driver == null) {} // wait for driver to be initialized
		driver.get(url);
		if (url.contains("mend.io"))
			return (String) ((JavascriptExecutor) driver).executeScript("return document.getElementsByTagName('html')[0].innerHTML");
		return driver.getPageSource();
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
		} catch (IOException ie) {
			ie.printStackTrace();
		}
		return pdfText;
	}

}
