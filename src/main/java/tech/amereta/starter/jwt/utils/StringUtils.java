package tech.amereta.starter.jwt.utils;

import org.apache.commons.codec.binary.Base64;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;

public class StringUtils {

    private final static String EMAIL_REGEX = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";

    public static String randomBase64(int size) {
        Random random = ThreadLocalRandom.current();
        byte[] r = new byte[size];
        random.nextBytes(r);
        return Base64.encodeBase64String(r);
    }

    public static boolean isValidEmail(String email) {
        return Pattern.compile(EMAIL_REGEX)
                .matcher(email)
                .matches();
    }
}
