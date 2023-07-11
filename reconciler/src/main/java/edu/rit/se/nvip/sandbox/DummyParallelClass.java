package edu.rit.se.nvip.sandbox;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

public class DummyParallelClass {

    public static void main(String[] args) {
        DummyParallelClass dummyParallel = new DummyParallelClass();

        // Create a set of jobs
        Set<String> jobs = new HashSet<>();
        jobs.add("1");
        jobs.add("2");

        dummyParallel.runJobsInHalfParallel(jobs);
    }
//prove data is altered, and you can grab it (callable vs runnable)
    public void runJobsInHalfParallel(Set<String> jobs) {
        List<Thread> reconcileThreadList = new ArrayList<>();
        for (String job : jobs) { //for each job

            Thread thread2 = new Thread(() -> { //thread that does step 2
                step2(job);
            });
            reconcileThreadList.add(thread2);

            step1(job);

            thread2.start(); //do step 2

        }

        for (Thread thread : reconcileThreadList) {
            try {
                thread.join(); //go through every thread to make sure they are complete
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void runJobsInFullParallel(Set<String> jobs) throws ExecutionException, InterruptedException {
        List<Callable<String>> jobThreads = new ArrayList<>();
        int i = 0;
        for (String job : jobs) {
            jobThreads.add(makeThreadFromJobId(job, i++));
        }
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        List<Future<String>> futures = new ArrayList<>();
        for (Callable<String> thread : jobThreads) {
            Future<String> future = executor.submit(thread);
            futures.add(future);
        }
        for (Future<String> future : futures) {
            future.get();
        }
        // wait for all the futures (executor method?)
        // go through the futures and grab their return values

    }

    private Callable<String> makeThreadFromJobId(String job, int jobid) {
        return new JobTask(job, jobid);
    }

    private class JobTask implements Callable<String> {
        String arg;
        int jobid;
        public JobTask(String arg, int jobid) {
            this.arg = arg;
            this.jobid = jobid;
        }

        @Override
        public String call() {
//            gptresourcemanager.filter(stuff, jobid);
//            gptresourcemanager.reconcile(stuff, jobid);
//            sendpnemessage();
            return arg + " just got called";
        }
    }

    public String step1(String job) { //mock filtering
        System.out.println("step 1 started for job " + job);
        try {
            Thread.sleep(1000);
            return job + " --- step one done";
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

    }

    public String step2(String job) { //mock reconciling
        System.out.println("step 2 started for job " + job);
        try {
            Thread.sleep(1000);
            return job + " --- step two done";
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
//        System.out.println("step 2 finished for job " + job);
    }
}