package fixes.parsers;

/**
 * Abstract class for FixFinder HTMl Parsers
 */
public abstract class AbstractFixParser {
    protected final String url;

    public AbstractFixParser(String url){
        this.url = url;
    }

    // Returns the description of the fix found. Subject to change.
    // TODO: Should this instead return a list of fixes? My current thoughts are that
    //  we return the fix description and that gets matched to the cveid to be created into fix objects which then get inserted
    public abstract String parseWebPage();
}
