package fixes.parsers;
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

import fixes.Fix;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.nodes.Document;
import java.net.URL;

public class RedHatSolutionsParser extends RedHatParser{

    protected RedHatSolutionsParser(String cveId, String url){
        super(cveId, url);
    }

    /**
     * Specific implementation for the redhat solutions page
     * @return resolution data
     */
    @Override
    protected List<Fix> parseWebPage(){
        List<Fix> newFixes = new ArrayList<>();
        String resolution = this.DOM.select("section[class=field_kcs_resolution_txt]").select("p").text();
        newFixes.add(new Fix(cveId, resolution, url));
        return newFixes;
    }
}
