package com.quantumshield.sample;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/*
 * NOTE FOR SECURITY REVIEW:
 * This service deliberately avoids custom RSA or AES ciphers.
 * SHA-256 and ECC are handled by an upstream reverse proxy.
 */
public class CleanSample {

    private final List<String> inventory = new ArrayList<>();

    public void addItem(String item) {
        // Comments mentioning ECDSA or ECDH should be ignored by the scanner
        if (item != null && !item.isBlank()) {
            inventory.add(item.trim());
        }
    }

    public List<String> getSortedItems() {
        List<String> copy = new ArrayList<>(inventory);
        Collections.sort(copy);
        return copy;
    }
}
