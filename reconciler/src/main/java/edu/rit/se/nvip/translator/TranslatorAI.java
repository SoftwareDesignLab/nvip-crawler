package edu.rit.se.nvip.translator;
import com.theokanning.openai.OpenAiHttpException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import edu.rit.se.nvip.cwe.CWETree;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.openai.OpenAIRequestHandler;
import edu.rit.se.nvip.openai.RequestorIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
public class TranslatorAI {
    private static final Logger logger = LogManager.getLogger(TranslatorAI.class.getSimpleName());
    private OpenAIRequestHandler requestHandler;
    private static final String MODEL = "gpt-3.5-turbo";
    private static final double TEMP = 0.0;
    private static final String SYS_MESSAGE = String.format("You are a helpful translator. You will be given a phrase in any language and your " +
            "goal is to translate it back to english.");
    private static final String SYS_ROLE = "system";
    private static final String USER_ROLE = "user";

    public TranslatorAI() {
        requestHandler = OpenAIRequestHandler.getInstance();
    }

    public static void main(String[] args) {
        TranslatorAI translator = new TranslatorAI();
        RawVulnerability vuln = new RawVulnerability(1, "cve-1",
                "mailcow es una suite de servidor de correo basada en Dovecot, Postfix y otro software de código abierto, que proporciona una interfaz de usuario web moderna " +
                        "para la administración de usuarios/servidores. Se ha descubierto una vulnerabilidad en mailcow que permite a un atacante manipular las variables internas de " +
                        "Dovecot mediante el uso de contraseñas especialmente diseñadas durante el proceso de autenticación. El problema surge del comportamiento del script " +
                        "`passwd-verify.lua`, que es responsable de verificar las contraseñas de los usuarios durante los intentos de inicio de sesión. Tras un inicio de sesión " +
                        "exitoso, el script devuelve una respuesta en el formato de \"contraseña = <contraseña válida>\", lo que indica la autenticación exitosa. Al crear una " +
                        "contraseña con pares clave-valor adicionales adjuntos, un atacante puede manipular la cadena devuelta e influir en el comportamiento interno de Dovecot. " +
                        "Por ejemplo, usar la contraseña \"123 mail_crypt_save_version=0\" haría que el script `passwd-verify.lua` devolviera la cadena \"password=123 " +
                        "mail_crypt_save_version=0\". En consecuencia, Dovecot interpretará esta cadena y establecerá las variables internas en consecuencia, lo que generará " +
                        "consecuencias no deseadas. Esta vulnerabilidad puede ser aprovechada por un atacante autenticado que tenga la capacidad de establecer su propia contraseña. " +
                        "La explotación exitosa de esta vulnerabilidad podría dar como resultado el acceso no autorizado a las cuentas de los usuarios, eludir los controles de seguridad " +
                        "u otras actividades maliciosas. Este problema se ha corregido en la versión `2023-05a`. Se recomienda a los usuarios que actualicen. No hay soluciones alternativas" +
                        " conocidas para esta vulnerabilidad.",
                new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()), "www.example.com");
        String response = translator.translate(vuln);
        logger.info(response);
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
    private String translate(RawVulnerability vuln){
        return callModel(vuln.getDescription());
    }
}
