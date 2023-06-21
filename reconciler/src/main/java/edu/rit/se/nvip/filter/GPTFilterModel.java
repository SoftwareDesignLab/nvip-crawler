package edu.rit.se.nvip.filter;

import com.knuddels.jtokkit.Encodings;
import com.knuddels.jtokkit.api.Encoding;
import com.knuddels.jtokkit.api.ModelType;
import com.mysql.cj.x.protobuf.MysqlxCursor;
import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.model.Model;
import com.theokanning.openai.service.OpenAiService;
import edu.rit.se.nvip.ReconcilerMain;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class GPTFilterModel {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    private static final String MODEL = "gpt-3.5-turbo";
    private static final double TEMP = 0.0;
    private static final String PASS = "0";
    private static final String FAIL = "1";
    private static final String SYS_MESSAGE = String.format("You are a validation engine for vulnerability data scraped from the web." +
            " If a user's message looks like a CVE description without errors, respond with \"%s\" or else \"%s\"", PASS, FAIL);
    private static final String SYS_ROLE = "system";
    private static final String USER_ROLE = "user";
    private static String KEY;

    public GPTFilterModel() {
        KEY = (String) ReconcilerMain.envVars.get("openaiKey");
    }

    public boolean testConnection() {
        // the listModels() includes an API call to account for any fine-tuned models, so this effectively validates the key and connection
        try {
            OpenAiService service = new OpenAiService(KEY);
            List<Model> models = service.listModels();
            return models.size() > 0;
        } catch (Exception ex) {
            logger.error("Could not connect to OpenAI. Check your connection or key");
            return false;
        }
    }

    public boolean callModel(String arg) throws OpenAiInvalidReturnException{
        try {
            List<ChatMessage> messages = formMessages(arg);
            OpenAiService service = new OpenAiService(KEY);
            ChatCompletionRequest request = ChatCompletionRequest.builder().model(MODEL).temperature(TEMP).n(1).messages(messages).maxTokens(1).build();
            ChatCompletionResult res = service.createChatCompletion(request);
            String answer = res.getChoices().get(0).getMessage().getContent();
            switch (answer) {
                case PASS:
                    return true;
                case FAIL:
                    return false;
                default:
                    throw new OpenAiInvalidReturnException("OpenAi responded with \"" + answer + "\"");
            }
        } catch (OpenAiHttpException ex) {
            logger.error(ex);
            return true;
        }
    }

    public int tokenCount(String description) {
        // this is not as simple as just tokenizing the openAI query because that query goes through some further processing on their end, adding tokens
        // numbers gotten from https://github.com/openai/openai-cookbook/blob/main/examples/How_to_count_tokens_with_tiktoken.ipynb
        Encoding enc = Encodings.newDefaultEncodingRegistry().getEncodingForModel(ModelType.GPT_3_5_TURBO);
        int tokensPerMsg = 4;
        int replyTokens = 3;
        List<ChatMessage> messages = formMessages(description);
        int tokenCount = 0;
        for (ChatMessage msg : messages) {
            tokenCount += tokensPerMsg;
            tokenCount += enc.encode(msg.getContent()).size();
            tokenCount += enc.encode(msg.getRole()).size();
        }
        tokenCount += replyTokens;
        return tokenCount;
    }

    private List<ChatMessage> formMessages(String description) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(SYS_ROLE, SYS_MESSAGE));
        messages.add(new ChatMessage(USER_ROLE, description));
        return messages;
    }

    public static class OpenAiInvalidReturnException extends Exception {
        public OpenAiInvalidReturnException(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class OpenAiException extends Exception {
        public OpenAiException(String errorMessage) {
            super(errorMessage);
        }
    }
}
