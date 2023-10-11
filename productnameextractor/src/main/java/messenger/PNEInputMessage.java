package messenger;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * An InputMessage is either an array of CVE jobs, or a plain string used as a command, such as "TERMINATE"
 */
public class PNEInputMessage {
    private List<PNEInputJob> jobs;
    private String command;

    public PNEInputMessage() {}

    public PNEInputMessage(List<PNEInputJob> jobs) {
        this.jobs = jobs;
    }

    @JsonSetter("jobs")
    public void setJobs(List<PNEInputJob> jobs) {
        this.jobs = jobs;
    }

    @JsonSetter("command")
    public void setCommand(String command) {
        this.command = command;
    }

    public List<PNEInputJob> getJobs() {
        return this.jobs;
    }

    public String getCommand() {
        return this.command;
    }

    public boolean hasJobArray() {
        return this.jobs != null;
    }

    public static void main(String[] args) throws JsonProcessingException {
        String msg = "{\"jobs\":[{\"cveId\":\"xxx\", \"vulnVersionId\":321}]}";
        PNEInputMessage im = new ObjectMapper().readValue(msg, PNEInputMessage.class);
        String msg2 = "{\"command\":\"terminate\"}";
        PNEInputMessage im2 = new ObjectMapper().readValue(msg2, PNEInputMessage.class);
        int a = 0;
    }
}
