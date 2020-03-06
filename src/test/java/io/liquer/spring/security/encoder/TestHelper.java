package io.liquer.spring.security.encoder;

/**
 * @author sius
 */
public final class TestHelper {

    private final static boolean DEBUG = false;
    public static void log(String data) {
        if (DEBUG) {
            System.out.println(data);
        }
    }
}
