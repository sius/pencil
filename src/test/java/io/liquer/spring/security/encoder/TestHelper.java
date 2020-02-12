package io.liquer.spring.security.encoder;

public final class TestHelper {

    private final static boolean DEBUG = true;
    public static void log(String data) {
        if (DEBUG) {
            System.out.println(data);
        }
    }
}
