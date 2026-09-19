/* Compiled against commons-io, but never referenced from App.class: App
 * loads this class reflectively, through a URLClassLoader it builds only
 * after the firing signal, which is what first opens that jar. See
 * App.runLazyLoad. */
import java.io.File;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.FileUtils;

public class LazyCommonsIoUser {
    public static String run() throws Exception {
        File f = new File("/opt/fixture-repo/digest-input.txt");
        String content = FileUtils.readFileToString(f, StandardCharsets.UTF_8);
        return String.valueOf(content.length());
    }
}
