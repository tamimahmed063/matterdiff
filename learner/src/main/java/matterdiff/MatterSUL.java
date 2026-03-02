package matterdiff;

import de.learnlib.sul.SUL;
import de.learnlib.exception.SULException;

import java.io.*;
import java.net.Socket;

public class MatterSUL implements SUL<String, String> {

    private static final String HOST = "127.0.0.1";
    private static final int    PORT = 7777;

    private Socket         sock;
    private BufferedReader in;
    private PrintWriter    out;

    private void connect() {
        try {
            sock = new Socket(HOST, PORT);
            in   = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            out  = new PrintWriter(new OutputStreamWriter(sock.getOutputStream()), true);
        } catch (IOException e) {
            throw new SULException(e);
        }
    }

    private String send(String msg) {
        out.println(msg);
        try {
            return in.readLine();
        } catch (IOException e) {
            throw new SULException(e);
        }
    }

    @Override
    public void pre() {
        if (sock == null || sock.isClosed()) {
            connect();
        }
        send("RESET");
    }

    @Override
    public void post() {
        send("DONE");
    }

    @Override
    public String step(String input) throws SULException {
        return send("STEP:" + input);
    }

    public void close() {
        try {
            if (sock != null && !sock.isClosed()) sock.close();
        } catch (IOException ignored) {}
    }
}