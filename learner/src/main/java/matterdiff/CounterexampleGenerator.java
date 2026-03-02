package matterdiff;

import net.automatalib.word.Word;
import java.util.*;

public class CounterexampleGenerator {

    private static final List<String> HAPPY_PATH = Arrays.asList(
        "COMM_ARM_FAILSAFE",
        "COMM_ATTESTATION_REQUEST",
        "COMM_CERT_CHAIN_REQUEST_DAC",
        "COMM_CERT_CHAIN_REQUEST_PAI",
        "COMM_CSR_REQUEST",
        "COMM_ADD_TRUSTED_ROOT_CERT",
        "COMM_ADD_NOC"
    );

    public static List<Word<String>> generateCommissioning() {
        List<Word<String>> seqs = new ArrayList<>();

        // 1. Happy path
        seqs.add(word(HAPPY_PATH));

        // 2. Skip each step
        for (int i = 0; i < HAPPY_PATH.size(); i++) {
            List<String> skipped = new ArrayList<>(HAPPY_PATH);
            skipped.remove(i);
            seqs.add(word(skipped));
        }

        // 3. Repeat each step
        for (int i = 0; i < HAPPY_PATH.size(); i++) {
            List<String> repeated = new ArrayList<>(HAPPY_PATH);
            repeated.add(i + 1, HAPPY_PATH.get(i));
            seqs.add(word(repeated));
        }

        // 4. Swap adjacent steps
        for (int i = 0; i < HAPPY_PATH.size() - 1; i++) {
            List<String> swapped = new ArrayList<>(HAPPY_PATH);
            Collections.swap(swapped, i, i + 1);
            seqs.add(word(swapped));
        }

        // 5. Start without ARM_FAILSAFE
        seqs.add(word("COMM_ATTESTATION_REQUEST"));
        seqs.add(word("COMM_CSR_REQUEST"));
        seqs.add(word("COMM_ADD_TRUSTED_ROOT_CERT"));
        seqs.add(word("COMM_ADD_NOC"));

        // 6. ARM_FAILSAFE only variants
        seqs.add(word("COMM_ARM_FAILSAFE"));
        seqs.add(word("COMM_ARM_FAILSAFE", "COMM_ARM_FAILSAFE"));

        // 7. Short paths skipping attestation entirely (key security finding)
        seqs.add(word("COMM_ARM_FAILSAFE", "COMM_CSR_REQUEST"));
        seqs.add(word("COMM_ARM_FAILSAFE", "COMM_CSR_REQUEST", "COMM_ADD_TRUSTED_ROOT_CERT", "COMM_ADD_NOC"));
        seqs.add(word("COMM_ARM_FAILSAFE", "COMM_ADD_TRUSTED_ROOT_CERT", "COMM_ADD_NOC"));
        seqs.add(word("COMM_ARM_FAILSAFE", "COMM_ADD_NOC"));

        // 8. Post-commissioning probes
        seqs.add(word(happyPathThen("COMM_ARM_FAILSAFE")));
        seqs.add(word(happyPathThen("COMM_ADD_NOC")));
        seqs.add(word(happyPathThen("COMM_CSR_REQUEST")));
        seqs.add(word(happyPathThen("COMM_ADD_TRUSTED_ROOT_CERT")));
        seqs.add(word(happyPathThen(
            "COMM_ARM_FAILSAFE",
            "COMM_CSR_REQUEST",
            "COMM_ADD_TRUSTED_ROOT_CERT",
            "COMM_ADD_NOC"
        )));

        return seqs;
    }

    private static List<String> happyPathThen(String... extra) {
        List<String> seq = new ArrayList<>(HAPPY_PATH);
        seq.addAll(Arrays.asList(extra));
        return seq;
    }

    private static Word<String> word(List<String> symbols) {
        return Word.fromSymbols(symbols.toArray(new String[0]));
    }

    private static Word<String> word(String... symbols) {
        return Word.fromSymbols(symbols);
    }
}