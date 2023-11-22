package fixes.urlfinders;

import env.FixFinderEnvVars;
import org.junit.jupiter.api.Test;

public abstract class FixUrlFinderTest<T extends FixUrlFinder> {
    final protected T fixUrlFinder;

    protected FixUrlFinderTest(T fixUrlFinder) {
        this.fixUrlFinder = fixUrlFinder;
        FixFinderEnvVars.initializeEnvVars(true);
    }

    @Test
    public abstract void testRun();
}
