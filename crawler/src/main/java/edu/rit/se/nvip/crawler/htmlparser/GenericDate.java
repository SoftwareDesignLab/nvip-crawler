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

package edu.rit.se.nvip.crawler.htmlparser;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GenericDate {

    private static final Map<Pattern, String> DATE_FORMATS;
    static {
        DATE_FORMATS = new HashMap<>();
        DATE_FORMATS.put(Pattern.compile("^\\d{8}$"), "yyyyMMdd");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}-\\d{1,2}-\\d{4}$"), "dd-MM-yyyy");
        DATE_FORMATS.put(Pattern.compile("([12]\\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01]))"), "yyyy-MM-dd");
        DATE_FORMATS.put(Pattern.compile("(0?[1-9]|1[012])[-\\/.](0?[1-9]|[12][0-9]|3[01])[-\\/.]((?:19|20)\\d\\d)"), "MM/DD/YYYY");
        DATE_FORMATS.put(Pattern.compile("^\\d{4}/\\d{1,2}/\\d{1,2}$"), "yyyy/MM/dd");
        DATE_FORMATS.put(Pattern.compile("([1-9]|[12]\\d|3[01])\\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s([12]\\d{3})"), "dd MMM yyyy");
        DATE_FORMATS.put(Pattern.compile("([1-9]|[12]\\d|3[01])\\s"
                + "(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|Nov(ember)?|Dec(ember)?)"
                + "\\s([12]\\d{3})"), "dd MMMM yyyy");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}\\s[a-z]{4,}\\s\\d{4}$"), "dd MMMM yyyy");
        DATE_FORMATS.put(Pattern.compile("^\\d{12}$"), "yyyyMMddHHmm");
        DATE_FORMATS.put(Pattern.compile("^\\d{8}\\s\\d{4}$"), "yyyyMMdd HHmm");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}-\\d{1,2}-\\d{4}\\s\\d{1,2}:\\d{2}$"), "dd-MM-yyyy HH:mm");
        DATE_FORMATS.put(Pattern.compile("^\\d{4}-\\d{1,2}-\\d{1,2}\\s\\d{1,2}:\\d{2}$"), "yyyy-MM-dd HH:mm");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}/\\d{1,2}/\\d{4}\\s\\d{1,2}:\\d{2}$"), "MM/dd/yyyy HH:mm");
        DATE_FORMATS.put(Pattern.compile("^\\d{4}/\\d{1,2}/\\d{1,2}\\s\\d{1,2}:\\d{2}$"), "yyyy/MM/dd HH:mm");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}\\s[a-z]{3}\\s\\d{4}\\s\\d{1,2}:\\d{2}$"), "dd MMM yyyy HH:mm");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}\\s[a-z]{4,}\\s\\d{4}\\s\\d{1,2}:\\d{2}$"), "dd MMMM yyyy HH:mm");
        DATE_FORMATS.put(Pattern.compile("^\\d{14}$"), "yyyyMMddHHmmss");
        DATE_FORMATS.put(Pattern.compile("^\\d{8}\\s\\d{6}$"), "yyyyMMdd HHmmss");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}-\\d{1,2}-\\d{4}\\s\\d{1,2}:\\d{2}:\\d{2}$"), "dd-MM-yyyy HH:mm:ss");
        DATE_FORMATS.put(Pattern.compile("^\\d{4}-\\d{1,2}-\\d{1,2}\\s\\d{1,2}:\\d{2}:\\d{2}$"), "yyyy-MM-dd HH:mm:ss");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}/\\d{1,2}/\\d{4}\\s\\d{1,2}:\\d{2}:\\d{2}$"), "MM/dd/yyyy HH:mm:ss");
        DATE_FORMATS.put(Pattern.compile("^\\d{4}/\\d{1,2}/\\d{1,2}\\s\\d{1,2}:\\d{2}:\\d{2}$"), "yyyy/MM/dd HH:mm:ss");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}\\s[a-z]{3}\\s\\d{4}\\s\\d{1,2}:\\d{2}:\\d{2}$"), "dd MMM yyyy HH:mm:ss");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}\\s[a-z]{4,}\\s\\d{4}\\s\\d{1,2}:\\d{2}:\\d{2}$"), "dd MMMM yyyy HH:mm:ss");
        DATE_FORMATS.put(Pattern.compile("(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*?\\s+\\d{1,2}(?:[a-z]{2})?(?:\\s+|,\\s*)\\d{4}\\b"), "MMMM dd, yyyy");
    }


    private LocalDate date;

    private String rawDate;

    /**
     * Encapsulates and parses a date parsed from a CNA
     * @param date - raw date to be parsed
     */
    public GenericDate(String date) {
        this.rawDate = matchRawDate(date);
        this.date = parseDate(date);
    }

    public LocalDate getDate() {
        return date;
    }

    public String getRawDate() {
        return rawDate;
    }

    public String matchRawDate(String dateString) {
        for (Pattern regexp : DATE_FORMATS.keySet()) {
            Matcher matcher = regexp.matcher(dateString);
            if (matcher.find()) {
                rawDate = matcher.group();
                return DATE_FORMATS.get(regexp);
            }
        }
        // fall through - try matching at least a month and year
        Pattern monthRegExp = Pattern.compile("(\\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\\b)\\s(\\d{4})");
        Matcher matcher = monthRegExp.matcher(dateString);
        if (matcher.find()) {
            rawDate = matcher.group();
            return "MMMM yyyy";
        }
        // Unknown format, return null
        return null;
    }

    public LocalDate parseDate(String date) {
        String format = matchRawDate(date);

        return null;
    }

}
