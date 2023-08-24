package fixes.parsers;

import fixes.Fix;

import java.util.List;

public class GenericParser extends AbstractFixParser{

    public GenericParser(String cveId, String url){
        super(cveId, url);
    }

    //TODO: implement some day
    @Override
    public List<Fix> parseWebPage() {
        return null;
    }
}
