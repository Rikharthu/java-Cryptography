package com.example.uberv;

import com.sun.istack.internal.Nullable;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Set;

public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}; // 0, 1, 2, ...

        // create a 64 bit secret key from raw bytes
        SecretKey key64 = new SecretKeySpec(
                new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
                "Blowfish");

        // Create a cipher and attempt to encrypt the data block with our key
        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");

        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);
        System.out.println("64 bit test: passed");

        // !ACHTUNG! this will fail if you don't have unlimited strength JCE policy files installed
        // create a 192 bit secret key from raw bytes
        SecretKey key192 = new SecretKeySpec(
                new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
                "Blowfish");
        // now try encrypting with the larger key
        c.init(Cipher.ENCRYPT_MODE, key192);
        c.doFinal(data);
        System.out.println("192 bit test: passed");

        System.out.println("Tests completed");


        printProviders();

        // Try to get BouncyCastle provider
        Provider bouncyCastle = findProvider("BC");
    }

    public static void printProviders() {
        System.out.println("Installed Security Providers:");
        // List installed providers in their priority order
        Provider[] installedProviders = Security.getProviders();
        String format = "%d\tName:\t%s\n\tVersion:\t%s\n\tInfo:\t%s\n\tClass:\t%s\n";
        for (int i = 0; i < installedProviders.length; i++) {
            Provider provider = installedProviders[i];
            int priority = i + 1; // getProviders() returns them ordered by priority
            System.out.printf(format,
                    priority,
                    provider.getName(),
                    provider.getVersion(),
                    provider.getInfo(),
                    provider.getClass().getName());
        }
    }

    @Nullable
    public static Provider findProvider(String name) {
        System.out.println("Searching for provider " + name);
        // find provider with specified name, returns null if not found
        Provider provider = Security.getProvider(name);
        if (provider != null) {
            System.out.println("Provider " + name + " has been found!");
            System.out.println(provider);
        } else {
            System.out.println("Provider " + name + " not found :(");
        }
        // TODO make separete print method
//        Set<String> supportedAlgorithms = Security.getAlgorithms("MessageDigest");
        return provider;
    }
}
