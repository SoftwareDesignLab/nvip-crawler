package fixes;

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


import java.util.ArrayList;

/**
 * Model class for fixes found by fixfinder
 */
public class Fix {
    // TODO: This
    private final String fix_id;
    private final String fix_url;
    private final String fix_description;
    private final String source_url_id;
    //store the source urls
    private final ArrayList<String> source_urls;

    /**
     * Model class for fix objects
     *
     * @param fix_id         the ID of the fix
     * @param fix_url        the URL of the fix
     * @param fix_description the description of the fix
     * @param source_url_id  the ID of the source URL
     * @param source_urls    the source URLs
     */
    public Fix(String fix_id, String fix_url, String fix_description, String source_url_id, ArrayList<String> source_urls) {
        super();
        this.fix_id = fix_id;
        this.fix_url = fix_url;
        this.fix_description = fix_description;
        this.source_url_id = source_url_id;
        this.source_urls = source_urls;
    }

    /**
     * @return the fix_id
     */
    public String getFix_id() {
        return fix_id;
    }

    /**
     * @return the fix_url
     */
    public String getFix_url() {
        return fix_url;
    }

    /**
     * @return the fix_description
     */
    public String getFix_description() {
        return fix_description;
    }

    /**
     * @return the source_url_id
     */
    public String getSource_url_id() {
        return source_url_id;
    }

    /**
     * @return the source_urls
     */
    public ArrayList<String> getSource_urls() {
        return source_urls;
    }

    /**
     * @return the source_urls as a string
     */
    public String getSource_urls_string() {
        String source_urls_string = "";
        for (String source_url : source_urls) {
            source_urls_string += source_url + "\n";
        }
        return source_urls_string;
    }

    /**
     * set the source_urls
     */
    public void setSource_urls(ArrayList<String> source_urls) {
        this.source_urls.clear();
        this.source_urls.addAll(source_urls);
    }

    /**
     * @return the fix as a string
     */
    public String toString() {
        return "Fix [fix_id=" + fix_id + ", fix_url=" + fix_url + ", fix_description=" + fix_description
                + ", source_url_id=" + source_url_id + ", source_urls=" + source_urls + "]";
    }
}