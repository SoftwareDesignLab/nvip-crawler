package edu.rit.se.nvip.openai;

import com.google.common.util.concurrent.RateLimiter;
import com.knuddels.jtokkit.Encodings;
import com.knuddels.jtokkit.api.Encoding;
import com.knuddels.jtokkit.api.ModelType;
import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.model.Model;
import com.theokanning.openai.service.OpenAiService;
import edu.rit.se.nvip.ReconcilerMain;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Optional;

public class OpenAIRequestHandler {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
    //https://platform.openai.com/account/rate-limits
    private static final ModelType DEFAULT_CHAT_COMPLETION_MODEL = ModelType.GPT_3_5_TURBO;
    private final static double TOKEN_RATE_LIMIT = 90000. / 60;
    private final static double REQUEST_RATE_LIMIT = 3500. /60;
    private static final RateLimiter tokenLimiter = RateLimiter.create(TOKEN_RATE_LIMIT);
    private static final RateLimiter requestLimiter = RateLimiter.create(REQUEST_RATE_LIMIT);
    private OpenAiService service;

    public OpenAIRequestHandler() {
        service = new OpenAiService((String) ReconcilerMain.envVars.get("openaiKey"));
    }

    public void setService(OpenAiService service) {
        // dependency injection allows easier testing
        this.service = service;
    }

    public boolean testConnection() {
        // the listModels() includes an API call to account for any fine-tuned models, so this effectively validates the key and connection without actually using any tokens
        try {
            List<Model> models = service.listModels();
            return models.size() > 0;
        } catch (Exception ex) {
            logger.error("Could not connect to OpenAI. Check your internet connection or key");
        }
        return false;
    }

    public ChatCompletionResult createChatCompletion(ChatCompletionRequest request) {
        waitForLimiters(chatCompletionTokenCount(request));
        try {
            return service.createChatCompletion(request);
        } catch (OpenAiHttpException ex) {
            // todo inspect and handle this, especially if it's a rate limit thing
            return null;
        }
    }

    public int chatCompletionTokenCount(ChatCompletionRequest request) {
        Optional<Encoding> optEnc = Encodings.newDefaultEncodingRegistry().getEncodingForModel(request.getModel());
        Encoding enc = optEnc.orElseGet(() -> Encodings.newDefaultEncodingRegistry().getEncodingForModel(DEFAULT_CHAT_COMPLETION_MODEL));
        return chatCompletionTokenCount(request.getMessages(), enc);
    }

    public int chatCompletionTokenCount(List<ChatMessage> messages, Encoding enc) {
        // this is not as simple as just tokenizing the openAI query because that query goes through some further processing on their end, adding tokens
        // numbers gotten from https://github.com/openai/openai-cookbook/blob/main/examples/How_to_count_tokens_with_tiktoken.ipynb
        int tokensPerMsg = 4;
        int tokenCount = 0;
        for (ChatMessage msg : messages) {
            tokenCount += tokensPerMsg;
            tokenCount += enc.encode(msg.getContent()).size();
            tokenCount += enc.encode(msg.getRole()).size();
        }
        return tokenCount;
    }

    public int chatCompletionTokenCount(ChatCompletionRequest request, int maxReplyTokens) {
        return chatCompletionTokenCount(request) + maxReplyTokens;
    }

    private void waitForLimiters(int tokens) {
        tokenLimiter.acquire(tokens);
        requestLimiter.acquire(1);
    }
}
