package edu.rit.se.nvip.sandbox;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class DummyParallelClass {
    private BlockingQueue<Integer> queue1;
    private BlockingQueue<Integer> queue2;

    public DummyParallelClass() {
        this.queue1 = new LinkedBlockingQueue<>();
        this.queue2 = new LinkedBlockingQueue<>();
    }

    public static void main(String[] args) {
        DummyParallelClass dummyParallel = new DummyParallelClass();

        // Create a set of jobs
        Set<Integer> jobs = new HashSet<>();
        jobs.add(1);
        jobs.add(2);
        jobs.add(3);

        dummyParallel.runJobsInHalfParallel(jobs);

        // Run the jobs in a half-parallel manner
//        for (int i = 5; i > 0; i--){
//            dummyParallel.runJobsInHalfParallel(jobs);
//        }
    }

    public void runJobsInHalfParallel(Set<Integer> jobs) {
        for (Integer job : jobs) {
            Thread thread1 = new Thread(() -> step1(job));
            Thread thread2 = new Thread(() -> step2(job));

            try {
                // Start thread1 first
                thread1.start();

                // Wait for thread1 to populate queue1 before starting thread2
                thread1.join();

                // Start thread2 after thread1 has populated queue1
                thread2.start();

                // Wait for both threads to complete
                thread2.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public void step1(int job) {
        try {
            // Perform step1 operation and put the result into queue1
            int result = job + 1;
            queue1.put(result);
            System.out.println("job finished");
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void step2(int job) {
        try {
            // Pull from queue1 and perform step2 operation
            int data = queue1.take();
            int result = data + 2;

            // Put the result into queue2
            queue2.put(result);

            // Finish the job
            System.out.println("Job " + job + " completed. Result: " + result);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}