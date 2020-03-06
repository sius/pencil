package io.liquer.spring.security.support;

import java.util.Arrays;

/**
 * RFC 4648
 *
 * @author sius
 */
public final class Base64Support {

    private static final int BASE64_CR_POS = 76;
    private static final String REPLACE_ALL_REGEX = "(\r?\n|\r)";
    private static final char[] BASE64_ALPHABET = {
            /*        0   1   2   3   4   5   6   7   8   9   A   B	  C	  D	  E	  F */
            /* 0_ */ 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
            /* 1_ */ 'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
            /* 2_ */ 'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
            /* 3_ */ 'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
            /* (pad) = */
    };
    private static final char[] BASE64UFS_ALPHABET = {
            /*        0   1   2   3   4   5   6   7   8   9   A   B	  C	  D	  E	  F */
            /* 0_ */ 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
            /* 1_ */ 'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
            /* 2_ */ 'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
            /* 3_ */ 'w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'
            /* (pad) = */
    };

    private Base64Support() { }
    /**
     * Calculates the Base64 overhead.
     * @param val a byte array
     * @return the Base64 overhead
     */
    public static double b64SpaceDrain(byte[] val) {
        return (double)b64Len(val)/val.length;
    }
    /**
     * Calculates the required Base64 String length.
     * @param val a byte array
     * @return the required Base64 String length
     */
    private static int b64Len(byte[] val) {
        return (4 * (val.length + 2 - ((val.length + 2) % 3)))/3;
    }
    private static int b64PadLen(byte[] val) {
        return (3 - (val.length  % 3)) % 3;
    }

    public static String b64Wrap(String b64val) {
        return wrap(b64val, BASE64_CR_POS);
    }

    /**
     *
     * @param b64Val base64 String
     * @param crPos CR Position
     * @return the wrapped base64 String
     */
    public static String wrap(String b64Val, int crPos) {
        int len = b64Val.length();
        char[] ret = new char[len];
        System.arraycopy(b64Val.toCharArray(), 0, ret , 0, len);
        int pos = 0;
        while ( (pos += crPos) < len) {
            char[] tmp = new char[ret.length+2];
            int r = pos;
            int n = ++pos;
            System.arraycopy(ret, 0, tmp, 0, r);
            System.arraycopy(ret, r, tmp, ++pos, ret.length-r);
            tmp[r] = '\r';
            tmp[n] = '\n';
            ret = tmp;
        }
        return String.valueOf(ret);
    }
    public static String unwrap(String b64val) {
        if (b64val == null) {
            return null;
        }
        return b64val.replaceAll(REPLACE_ALL_REGEX, "");
    }
    /**
     * Prints a standard Base64 String
     *
     * @param val a byte array to encode
     * @return a standard Base64 String from the byte array
     */
    public static String base64Encode(byte[] val) {
        return base64Encode(BASE64_ALPHABET, val, false);
    }
    /**
     * Prints an URL encoded and file save Base64 String with padding ('='):
     * replaces the characters '+' and '/' with
     * '-' and '_'.
     * @param val a byte array to encode
     * @return an URL and file save Base64 String
     */
    public static String base64UfsEncode(byte[] val) {
        return base64Encode(BASE64UFS_ALPHABET, val, false);
    }

    /**
     * Prints an URL encoded Base64 String without padding:
     * replaces the characters '+' and '/' with
     * '-' and '_'.
     * @param val a byte array to encode
     * @return an URL encoded Base64 String without padding
     */
    public static String base64UrlEncode(byte[] val) {
        return base64Encode(BASE64UFS_ALPHABET, val, true);
    }

    /**
     *
     * @param val a byte array to encode
     * @param ufsSafe exclude padding if true
     * @param noPadding exclude padding if true
     * @return the bas64 encoded bytes
     */
    public static String base64Encode(byte[] val, boolean ufsSafe, boolean noPadding) {
        return base64Encode((ufsSafe ? BASE64UFS_ALPHABET : BASE64_ALPHABET), val, noPadding);
    }
    /**
     *
     * @param cp Base64 char point LOOKUP_TABLE
     * @param val a byte array to encode
     * @param noPadding exclude padding if true
     * @return the bas64 encoded bytes
     */
    public static String base64Encode(char[] cp, byte[] val, boolean noPadding) {
        if (val == null) {
            return null;
        }
        int pLen = b64PadLen(val);
        int len = b64Len(val);
        byte[] tmp = new byte[val.length+pLen];
        System.arraycopy(val, 0, tmp, 0, val.length);
        char[] ret = new char[len];
        for (int i = 0, j = 0; i < tmp.length; i+=3, j+=4) {
            int k    = ((tmp[i] & 0xff)<< 16) | ((tmp[i+1] & 0xff) << 8) | (tmp[i+2] & 0xff);
            ret[j]   = cp[((k >>> 18) & 0x3f)];
            ret[j+1] = cp[((k >>> 12) & 0x3f)];
            ret[j+2] = cp[((k >>>  6) & 0x3f)];
            ret[j+3] = cp[( k         & 0x3f)];
        }

        for (int l = len - pLen; l < len; l++) {
            ret[l] = '=';
        }
        return String.valueOf((noPadding)
                ? Arrays.copyOfRange(ret, 0, len - pLen)
                : ret);
    }
    /**
     * Parses Base64 and Base64 UFS (URL and file save Base64 with or without padding)
     * @param val a String value
     * @return the parsed byte array or an empty byte array
     */
    public static byte[] base64Decode(String val) {
        if (val == null) {
            return new byte[0];
        }
        char[] arr = val.toCharArray();
        int padLen = b64PadLen(arr);
        int cPadLen = b64SkippedPadLen(arr, padLen);
        if (cPadLen != padLen) {
            char[] tmp = new char[arr.length + cPadLen];
            System.arraycopy(arr, 0, tmp, 0, arr.length);
            for (int i = arr.length; i < tmp.length; i++) {
                tmp[i] = '=';
            }
            padLen = cPadLen;
            arr = tmp;
        }
        int len = (3 * arr.length / 4);
        int rLen = len - padLen;
        byte[] tmp = new byte[len];
        byte[] ret = new byte[rLen];
        for (int i = 0, j = 0; i < arr.length; i+=4, j+=3) {
            int l    = i+1, m = i+2, n = i+3;
            int o 	 = ((b64CpIndexOf(arr[i], i, rLen) & 0x3f) << 18) | ((b64CpIndexOf(arr[l], l, rLen) & 0x3f) << 12) |
                    ((b64CpIndexOf(arr[m], m, rLen) & 0x3f) << 6 ) |  (b64CpIndexOf(arr[n], n, rLen) & 0x3f);
            tmp[j]   = (byte)((o >>> 16) & 0xff);
            tmp[j+1] = (byte)((o >>>  8) & 0xff);
            tmp[j+2] = (byte)( o         & 0xff);
        }
        System.arraycopy(tmp, 0, ret, 0, rLen);
        return ret;
    }
    /* returns the Code Point index or throws an InvalidArgumentException if not found */
    private static int b64CpIndexOf(char val, int pos, int rLen) {
        final int i = val;
        if (i == 0x2b || i == 0x2d) {
            return 0x3e;
        }
        if (i == 0x2f || i == 0x5f) {
            return 0x3f;
        }
        if (i > 0x2f && i < 0x3a)   {
            return 0x34 + i - 0x30;
        }
        if (i > 0x40 && i < 0x5b)   {
            return i - 0x41;
        }
        if (i > 0x60 && i < 0x7b)   {
            return 0x1a + i - 0x61;
        }
        if (i == '"' && i <= rLen)  {
            throw new IllegalArgumentException(String.format("Invalid character: '%1$c' at position %2$d!", val, pos));
        }
        return 0;
    }

    private static int b64PadLen(char[] val) {
        int ret = 0;
        if (val[val.length-1] == '=') {
            ret++;
        }
        if (val[val.length-2] == '=') {
            ret++;
        }
        return ret;
    }

    private static int b64SkippedPadLen(char[] val, int padLen) {
        return (padLen > 0) ? padLen : (4 - val.length % 4) % 4;
    }
}
