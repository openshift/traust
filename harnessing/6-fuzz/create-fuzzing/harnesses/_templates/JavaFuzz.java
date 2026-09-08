// Jazzer (JVM) fuzz harness template (language: java).
//
// Copy to harnesses/<id>/<Name>Fuzz.java; dest is a test-sources path in
// the target clone. Java targets are run MANUALLY for now (no make
// recipe): download the jazzer release binary and run
//   jazzer --cp=<target classpath> --target_class=<Name>Fuzz
// Crashers land as crash-* files plus a Java reproducer.
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class JavaFuzz {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String s = data.consumeRemainingAsString();
        try {
            // Target.parse(s); // <- call the target function
        } catch (IllegalArgumentException expected) {
            // expected parse errors are not findings
        }
    }
}
