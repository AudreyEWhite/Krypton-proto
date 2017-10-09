/**
 * A Java-based implementation of the HC-256 Stream Cipher introduced in
 * Hongjun Wu's 2004 paper "A New Stream Cipher HC-256."
 *
 *
 *  
 * @Author Audrey White (AudreyEWhite9@gmail.com)
 * Last updated October 8, 2017
 */

package net.metricspace.crypto.ciphers.stream.salsa;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * A class for generating and updating HC-256's Keystream.
 * Will eventually subclass KeyGeneratorSpi
 */
public class HC256KeystreamGenerator { // extends KeyGeneratorSpi {
    /**
     * The random source.
     */
    private SecureRandom random;

		/**
		 * Performs one update on one entry in the keystream table. Returns void because
		 * table will already be updated.
		 *
		 * @Param T			Table to update.
		 * @Param r			Entry in table to update
		 */
		public static void singleUpdate(int r, int[] T) {
			T[r] = T[r] + T[(r + 10)%T.length];
			// T[r] = T[r] + (This line requires bit-shifting)

    /**
     * Generate a key from the concrete key material provided.  It is
     * safe to take possession of the array passed in.
     *
     * I will implement this method later. At the moment, I am uncertain how.
     *
     * @param data The concrete key material.
     * @return The generated key.
     */
    // protected abstract SecretKey engineGenerateKey(final byte[] data);

    /**
     * {@inheritDoc}
     */
    @Override
    protected final SecretKey engineGenerateKey() {
        final byte[] bytes = new byte[HC256KeystreamGenerator.KEY_LEN];

        try {
            random.nextBytes(bytes);

            return engineGenerateKey(bytes);
        } finally {
            Arrays.fill(bytes, (byte)0);
        }
    }

    /**
     * Initializes the key generator with the given random source.
     * The {@link AlgorithmParameterSpec} is not used.
     *
     * @param spec Ignored.
     * @param random The random source.
     */
    @Override
    protected final void engineInit(final AlgorithmParameterSpec spec,
                                    final SecureRandom random) {
        engineInit(random);
    }

    /**
     * Initializes the key generator with the given random source.
     * The key size parameter is ignored.
     * 
		 * To implement
		 *
     * @param keysize Ignored.
     * @param random The random source.
     */
    @Override
    protected final void engineInit(final int keysize,
                                    final SecureRandom random) {
        engineInit(random);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected final void engineInit(final SecureRandom random) {
        this.random = random;
    }
}
