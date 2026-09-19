/* Compiled against the jackson-databind/-core/-annotations trio, but
 * never referenced from App.class: App loads this class reflectively,
 * through a URLClassLoader it builds only after the firing signal, which
 * is what first opens those three jars. See App.runLazyLoad. */
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;

public class LazyJacksonUser {
    public static String run() throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("case", 28);
        payload.put("group", "used_lazily");
        return new ObjectMapper().writeValueAsString(payload);
    }
}
