package edu.rit.se;

import edu.rit.se.commits.JGitParser;

import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;

public class JGitThread extends Thread {
    private ArrayBlockingQueue<String> allRepos;
    private String clonePath;
    private ArrayList<String> cveIds;
    private JGitParser myParser;

    public JGitThread(ArrayBlockingQueue<String> repos, String cP, ArrayList<String> cveIds){
        this.allRepos=repos;
        this.clonePath=cP;
        this.cveIds = cveIds;
    }
    public void run(){
        for (String cveId : cveIds) {
            try {
                String r = this.allRepos.poll();
                //System.out.println(r);
                if (r != null) {
                    this.myParser = new JGitParser(r + ".git", this.clonePath);
                    this.myParser.cloneRepository();
                    //Thread.sleep(1000);
                    this.myParser.parseCommits(cveId);
                    this.myParser.deleteRepository();
                }
            } catch (Exception e) {
                System.err.println(e.toString());
            }
        }
    }
}
