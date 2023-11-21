package edu.rit.se.nvip.reconciler.openai;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletableFuture;

public class RequestWrapper implements Comparable<RequestWrapper> {
    ChatCompletionRequest request;
    CompletableFuture<ChatCompletionResult> futureResult;
    RequestorIdentity requestor;
    int priority;
    public RequestWrapper(ChatCompletionRequest request, CompletableFuture<ChatCompletionResult> futureResult, RequestorIdentity requestor, int priority) {
        this.request = request;
        this.futureResult = futureResult;
        this.requestor = requestor;
        this.priority = priority;
    }

    @Override
    public int compareTo(@NotNull RequestWrapper o) {
        if (this.requestor == o.requestor) {
            return this.priority - o.priority;
        }
        return this.requestor.compareTo(o.requestor);
    }
}
