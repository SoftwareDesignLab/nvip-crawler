package messenger;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class PFInputMessage {
    private List<PFInputJob> jobs;
    private String command;

    public PFInputMessage() {}

    public PFInputMessage(String command, List<PFInputJob> jobs) {
        this.command = command;
        this.jobs = jobs;
    }

    public PFInputMessage(List<PFInputJob> jobs) {
        this.command = "NORMAL";
        this.jobs = jobs;
    }

    @JsonSetter("jobs")
    public void setJobs(List<PFInputJob> jobs) {
        this.jobs = jobs;
    }

    @JsonSetter("command")
    public void setCommand(String command) {
        this.command = command;
    }

    public List<PFInputJob> getJobs() {
        return this.jobs;
    }

    public String getCommand() {
        return this.command;
    }

    public boolean hasJobArray() {
        return this.jobs != null;
    }
    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return "";
        }
    }
}
