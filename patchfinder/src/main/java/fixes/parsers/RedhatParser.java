package fixes.parsers;

import fixes.Fix;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RedhatParser extends FixParser {

    protected RedhatParser(String cveId, String url) {
        super(cveId, url);
    }

    @Override
    public List<Fix> parseWebPage() throws IOException {
        return new ArrayList<>();
    }
}
