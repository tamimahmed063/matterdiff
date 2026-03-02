package matterdiff;

import de.learnlib.algorithm.ttt.mealy.TTTLearnerMealy;
import de.learnlib.acex.AcexAnalyzers;
import de.learnlib.oracle.MembershipOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.learnlib.query.DefaultQuery;
import de.learnlib.query.Query;
import net.automatalib.alphabet.Alphabet;
import net.automatalib.alphabet.Alphabets;
import net.automatalib.automaton.transducer.MealyMachine;
import net.automatalib.serialization.dot.GraphDOT;
import net.automatalib.word.Word;
import net.automatalib.word.WordBuilder;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class MatterLearner {

    private static final String CACHE_DIR = System.getProperty("user.home") + "/matterdiff/cache";

    public static void main(String[] args) throws IOException {
        String phase     = args.length > 0 ? args[0] : "PASE";
        String dotFile   = System.getProperty("user.home") + "/matterdiff/fsm/" + phase.toLowerCase() + "_fsm.dot";
        String cacheFile = CACHE_DIR + "/" + phase.toLowerCase() + "_cache.log";

        Files.createDirectories(Paths.get(CACHE_DIR));
        Files.createDirectories(Paths.get(System.getProperty("user.home") + "/matterdiff/fsm"));

        Alphabet<String> alphabet = buildAlphabet(phase);
        MatterSUL sul = new MatterSUL();

        MembershipOracle.MealyMembershipOracle<String, String> sulOracle = new SULOracle<>(sul);

        SmartCachingOracle oracle = new SmartCachingOracle(sulOracle, cacheFile);

        TTTLearnerMealy<String, String> learner =
            new TTTLearnerMealy<>(alphabet, oracle, AcexAnalyzers.BINARY_SEARCH_BWD);

        MealyMachine<?, String, ?, String> fsm =
            runGuidedLearning(learner, oracle, alphabet, phase);

        System.out.println("States  : " + fsm.size());
        System.out.println("Hits    : " + oracle.hits);
        System.out.println("Misses  : " + oracle.misses);

        try (FileWriter fw = new FileWriter(dotFile)) {
            GraphDOT.write(fsm, alphabet, fw);
        }
        System.out.println("FSM -> " + dotFile);

        sul.close();
    }

    static MealyMachine<?, String, ?, String> runGuidedLearning(
            TTTLearnerMealy<String, String> learner,
            SmartCachingOracle oracle,
            Alphabet<String> alphabet,
            String phase) {

        learner.startLearning();

        List<Word<String>> counterexamples = buildCounterexamples(phase);
        int round = 0;

        while (true) {
            MealyMachine<?, String, ?, String> hyp = learner.getHypothesisModel();
            round++;

            DefaultQuery<String, Word<String>> ce = null;

            for (Word<String> seq : counterexamples) {
                Word<String> hypOut = hyp.computeOutput(seq);
                DefaultQuery<String, Word<String>> q = new DefaultQuery<>(seq);
                oracle.processQueries(Collections.singletonList(q));
                if (!hypOut.equals(q.getOutput())) {
                    ce = q;
                    break;
                }
            }

            if (ce == null) {
                System.out.printf("[Round %02d] Done.%n", round);
                return hyp;
            }

            System.out.printf("[Round %02d] CE: %s  hyp=%s  sul=%s%n",
                round,
                wordToStr(ce.getInput()),
                wordToStr(hyp.computeOutput(ce.getInput())),
                wordToStr(ce.getOutput()));

            boolean refined = learner.refineHypothesis(ce);
            if (!refined) {
                System.out.printf("[Round %02d] WARNING: TTT did not refine. Skipping.%n", round);
                counterexamples.remove(ce.getInput());
                if (counterexamples.isEmpty()) {
                    System.out.println("No more counterexamples — returning current hypothesis.");
                    return learner.getHypothesisModel();
                }
            }
        }
    }

    static class SmartCachingOracle
            implements MembershipOracle.MealyMembershipOracle<String, String> {

        private final MembershipOracle.MealyMembershipOracle<String, String> delegate;
        private final String cacheFile;
        private final Map<String, Word<String>> cache = new LinkedHashMap<>();
        long hits   = 0;
        long misses = 0;

        SmartCachingOracle(MembershipOracle.MealyMembershipOracle<String, String> delegate,
                           String cacheFile) throws IOException {
            this.delegate  = delegate;
            this.cacheFile = cacheFile;
            loadFromFile();
        }

        private void loadFromFile() throws IOException {
            Path p = Paths.get(cacheFile);
            if (!Files.exists(p)) return;
            try (BufferedReader br = Files.newBufferedReader(p)) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    String[] parts = line.split("\\|", 2);
                    if (parts.length != 2) continue;
                    Word<String> input  = strToWord(parts[0]);
                    Word<String> output = strToWord(parts[1]);
                    if (input.isEmpty() || output.isEmpty()) continue;
                    if (input.size() != output.size()) continue;
                    cache.put(parts[0].trim(), output);
                }
            }
            System.out.println("Loaded " + cache.size() + " queries from cache.");
        }

        private void writeEntry(Word<String> input, Word<String> output) {
            try (BufferedWriter bw = Files.newBufferedWriter(
                    Paths.get(cacheFile),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND)) {
                bw.write(wordToStr(input) + "|" + wordToStr(output));
                bw.newLine();
                bw.flush();
            } catch (IOException e) {
                System.err.println("Cache write error: " + e.getMessage());
            }
        }

        @Override
        public void processQueries(Collection<? extends Query<String, Word<String>>> queries) {
            for (Query<String, Word<String>> q : queries) {
                if (!(q instanceof DefaultQuery)) continue;
                DefaultQuery<String, Word<String>> dq = (DefaultQuery<String, Word<String>>) q;

                Word<String> prefix = dq.getPrefix();
                Word<String> suffix = dq.getSuffix();
                Word<String> full   = prefix.concat(suffix);
                String fullKey      = wordToStr(full);

                if (cache.containsKey(fullKey)) {
                    Word<String> fullOutput = cache.get(fullKey);
                    dq.answer(fullOutput.suffix(suffix.size()));
                    hits++;
                    System.out.printf("[HIT  #%04d] %s%n", hits, fullKey);
                } else {
                    misses++;
                    System.out.printf("[MISS #%04d] %s  -- querying device%n", misses, fullKey);

                    DefaultQuery<String, Word<String>> deviceQuery = new DefaultQuery<>(full);
                    delegate.processQueries(Collections.singletonList(deviceQuery));

                    Word<String> fullOutput = deviceQuery.getOutput();
                    System.out.printf("[MISS #%04d] %s  -- device: %s%n", misses, fullKey, wordToStr(fullOutput));

                    if (fullOutput != null && fullOutput.size() == full.size()) {
                        cache.put(fullKey, fullOutput);
                        writeEntry(full, fullOutput);
                        dq.answer(fullOutput.suffix(suffix.size()));
                    } else {
                        WordBuilder<String> wb = new WordBuilder<>();
                        for (int i = 0; i < suffix.size(); i++) wb.add("SESSION_ERROR");
                        dq.answer(wb.toWord());
                    }
                }
            }
        }
    }

    static List<Word<String>> buildCounterexamples(String phase) {
        List<Word<String>> seqs = new ArrayList<>();
        switch (phase.toUpperCase()) {
            case "PASE":
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PAKE3"));
                seqs.add(Word.fromSymbols("PASE_PAKE1"));
                seqs.add(Word.fromSymbols("PASE_PAKE3"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE3"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PBKDF_REQUEST"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PAKE1"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PBKDF_REQUEST"));
                seqs.add(Word.fromSymbols("PASE_PAKE1", "PASE_PAKE3"));
                seqs.add(Word.fromSymbols("PASE_PAKE3", "PASE_PAKE3"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PAKE3", "PASE_PBKDF_REQUEST"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PAKE3", "PASE_PAKE1"));
                seqs.add(Word.fromSymbols("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PAKE3", "PASE_PAKE3"));
                break;
            case "COMMISSIONING":
                seqs.addAll(CounterexampleGenerator.generateCommissioning());
                break;
            case "CASE":
                seqs.add(Word.fromSymbols("CASE_SEND_SIGMA1", "CASE_SEND_SIGMA3"));
                seqs.add(Word.fromSymbols("CASE_SEND_SIGMA3"));
                seqs.add(Word.fromSymbols("CASE_SEND_SIGMA1", "CASE_SEND_SIGMA1"));
                break;
        }
        return seqs;
    }

    static String wordToStr(Word<String> w) {
        if (w == null || w.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < w.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(w.getSymbol(i));
        }
        return sb.toString();
    }

    static Word<String> strToWord(String s) {
        if (s == null || s.trim().isEmpty()) return Word.epsilon();
        WordBuilder<String> wb = new WordBuilder<>();
        for (String sym : s.split(",")) wb.add(sym.trim());
        return wb.toWord();
    }

    private static Alphabet<String> buildAlphabet(String phase) {
        List<String> symbols;
        switch (phase.toUpperCase()) {
            case "PASE":
                symbols = Arrays.asList("PASE_PBKDF_REQUEST", "PASE_PAKE1", "PASE_PAKE3");
                break;
            case "COMMISSIONING":
                symbols = Arrays.asList(
                    "COMM_ARM_FAILSAFE", "COMM_ATTESTATION_REQUEST",
                    "COMM_CERT_CHAIN_REQUEST_DAC", "COMM_CERT_CHAIN_REQUEST_PAI",
                    "COMM_CSR_REQUEST", "COMM_ADD_TRUSTED_ROOT_CERT", "COMM_ADD_NOC");
                break;
            case "CASE":
                symbols = Arrays.asList("CASE_SEND_SIGMA1", "CASE_SEND_SIGMA3");
                break;
            default:
                throw new IllegalArgumentException("Unknown phase: " + phase);
        }
        return Alphabets.fromList(symbols);
    }
}