package edu.rit.se.nvip.cwe;

import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.openai.OpenAIRequestHandler;
import edu.rit.se.nvip.openai.RequestorIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class ChatGPTProcessor {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private OpenAIRequestHandler requestHandler;
    private static final String MODEL = "gpt-3.5-turbo";
    private static final double TEMP = 0.0;
    private static final String SYS_MESSAGE = String.format("You will be presented with several CWE IDs, their names, and their descriptions followed by a CVE description." +
            " Your job is to provide a list, from the CWE IDs given to you, of CWE IDs that you are 100 percent sure could be categorized with the CVE description," +
            " if you believe that none of the given CWE IDs match based on their name then simply respond \"NONE\" otherwise send ONLY a comma separated list of CWE Ids that match." +
            " if you ever send a CWE's name you have failed your job.");
    private static final String SYS_ROLE = "system";
    private static final String USER_ROLE = "user";
    private Set<String> processedIds = new HashSet<>();
    private Set<CWETree> out = new HashSet<>();
    private Set<CWETree> matches = new HashSet<>();
    private Set<Integer> matchedIds = new HashSet<>();
    public ChatGPTProcessor() {
        requestHandler = OpenAIRequestHandler.getInstance();
    }

    public String callModel(String arg) {
        try {
            ChatCompletionRequest request = formRequest(arg);
            Future<ChatCompletionResult> futureRes = requestHandler.createChatCompletion(request, RequestorIdentity.FILTER);
            ChatCompletionResult res = futureRes.get();
            return res.getChoices().get(0).getMessage().getContent();// Return the obtained result

        } catch (OpenAiHttpException | InterruptedException | ExecutionException ex) {
            logger.error(ex);
            return null;
        }
    }
    private ChatCompletionRequest formRequest(String description) {
        List<ChatMessage> messages = formMessages(description);
        return ChatCompletionRequest.builder().model(MODEL).temperature(TEMP).n(1).messages(messages).maxTokens(1000).build();
    }

    private List<ChatMessage> formMessages(String description) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(SYS_ROLE, SYS_MESSAGE));
        messages.add(new ChatMessage(USER_ROLE, description));
        return messages;
    }
    private Set<String> askChatGPT(Set<CWETree> candidates, CompositeVulnerability vuln){
        StringBuilder cwes = new StringBuilder(); //String that will be sent to chat gpt
        int count = 1; //count so we can ensure only 5 vulns get sent at a time (attempts to not overwhelm chatgpt)
        Set<String> out = new HashSet<>(); //the output set
        for (CWETree tree : candidates) {
            cwes.append(tree.getRoot().getId()).append(" ").append(tree.getRoot().getName()).append(": ").append(tree.getRoot().getDescription()); //append this string in the form{ 123: Cwe Name, 456: Cwe Name2, ...}
            if (count % 5 == 0) { //when 5 vulns are added to the cwe string
                String chatMessage = cwes + " \nCVE Description: \n" + vuln.getDescription(); //create the message to send to chat gpt
                String msg = callModel(chatMessage); //call chatgpt
                out.addAll(getIdsFromResponse(msg)); //add a set of ids from chat gpt to the output set
                cwes = new StringBuilder(); //clear out previous cwes
            }
            count++;

        }
        if (cwes.length() > 0){ //case for if there are 4-1 vulns left... AKA cwes.length is only zero if there are no CWEs left
            String chatMessage = cwes + " CVE Description: " + vuln.getDescription(); //create message to send to chat gpt
            String finalRun = callModel(chatMessage); //send it
            out.addAll(getIdsFromResponse(finalRun)); //add the response to the list of outputs
        }
        return out;
    }
    private Set<CWETree> parseResponse(Set<CWETree> candidates, Set<String> response){
        Set<CWETree> set = new HashSet<>();
        if(response.contains("NONE") || response.isEmpty()){
            return set;
        }
        for (String id : response){ //for each id
            for(CWETree cweTree : candidates){ //for each candidate id
                try {
                    if(id.equals("NONE") || id.equals("")) continue;
                    if (cweTree.getRoot().getId() == Integer.parseInt(id)) { //if the root id matches the id present then add the tree to the set of trees
                        set.add(cweTree);
                    }
                }catch(NumberFormatException e){
                    logger.error("Wrong format: {}", id); //in case chatgpt sends some weird format
                    break;
                }
            }
        }
        return set;
    }
    private Set<CWETree> whichMatchHelper(Set<CWETree> candidates, CompositeVulnerability vuln) {
        if (candidates.isEmpty()) { //if candidates is empty return a new set
            return new HashSet<>();
        }
        Set<String> response = askChatGPT(candidates, vuln); //ask chatgpt what candidates might be related to the cve
        Set<String> filteredResponse = new HashSet<>();
        if(!response.isEmpty()) {
            for (String id : response) {
                if(id.equals("NONE") || id.equals("")){
                    break;
                }
                if (!processedIds.contains(id)) { //keeps repeats from being sent
                    processedIds.add(id);
                    filteredResponse.add(id);
                }
            }
        }
        matches.addAll(parseResponse(candidates, filteredResponse)); //parse chatgpt's response

        List<CWETree> treesToProcess = new ArrayList<>(matches);
        for (CWETree match : treesToProcess) {
            if(!matchedIds.contains(match.getRoot().getId())) {
                matchedIds.add(match.getRoot().getId());
                out.add(match);
                whichMatchHelper(match.getSubtrees(), vuln);
            }
        }
        return out;
    }

    public Set<CWE> assignCWEs(CompositeVulnerability vuln) {

        CWEForest forest = new CWEForest(); // builds the forest
        Set<CWETree> trees = whichMatchHelper(forest.getTrees(), vuln); //gets trees related to vuln
        logger.info("trees size: " + trees.size());
        Set<CWE> out = new HashSet<>();
        for (CWETree tree : trees) {
            out.add(tree.getRoot());
        }
        return out;
    }
    private Set<String> getIdsFromResponse(String response) {

        String[] parts = response.split(","); //split the string by commas (the response string will look like{ 123,456,789 }
        Set<String> out = new HashSet<>(); //output set

        for (String part : parts) { //for each id
            String[] finalParts = part.split("CWE-"); //split one more time (occasionally chatgpt will send {CWE-123,CWE-456} instead so this accounts for that)
            for (String finalPart : finalParts){ //for finalPart or the final ID
                String trimmedPart = finalPart.trim(); //trim it
                if (trimmedPart.equals("")) continue;
                out.add(trimmedPart); //add the trimmed part to the list
            }
        }
        return out;
    }
    public static boolean isInt(String input) {
        try {
            Integer.parseInt(input);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

}
