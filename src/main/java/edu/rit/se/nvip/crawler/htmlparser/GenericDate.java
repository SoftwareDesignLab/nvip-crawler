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
        DATE_FORMATS.put(Pattern.compile("^\\d{4}-\\d{1,2}-\\d{1,2}$"), "yyyy-MM-dd");
        DATE_FORMATS.put(Pattern.compile("(0?[1-9]|1[012])[- \\/.](0?[1-9]|[12][0-9]|3[01])[- \\/.]((?:19|20)\\d\\d)"), "MM/DD/YYYY");
        DATE_FORMATS.put(Pattern.compile("^\\d{4}/\\d{1,2}/\\d{1,2}$"), "yyyy/MM/dd");
        DATE_FORMATS.put(Pattern.compile("^\\d{1,2}\\s[a-z]{3}\\s\\d{4}$"), "dd MMM yyyy");
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
        DATE_FORMATS.put(Pattern.compile("(\\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\\b)\\s(\\d{4})"), "MMMM YYYY");
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
        return null; // Unknown format.
    }

    public LocalDate parseDate(String date) {
        String format = matchRawDate(date);
        return null;
    }

}
