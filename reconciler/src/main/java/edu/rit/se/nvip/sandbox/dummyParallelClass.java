package edu.rit.se.nvip.sandbox;

import java.util.Set;

public class dummyParallelClass {
    public void runJobsInHalfParallel(Set<String> jobs) {
        // do step1 for job n+1 while you do step2 for job n
    }

    public void step1(String job) {
        //pull from some dummy queue

        //do something

        //put into second dummy queue

        //end job
    }
    public void step2(String job) {
        //pull from second dummy queue

        //do something else

        //finish

    }
}

