package edu.rit.se.nvip.openai;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

public class RequestWrapper implements Comparable<RequestWrapper> {
    int priority;
    ChatCompletionRequest request;
    CompletableFuture<ChatCompletionResult> futureResult;
    public RequestWrapper(int priority, ChatCompletionRequest request, CompletableFuture<ChatCompletionResult> futureResult) {
        this.priority = priority;
        this.request = request;
        this.futureResult = futureResult;
    }

    @Override
    public int compareTo(@NotNull RequestWrapper o) {
        return this.priority - o.priority;
    }
}
