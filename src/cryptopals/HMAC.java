package cryptopals;

import java.util.Arrays;

public class HMAC {
	SHA1 hash;

	public final int BLOCK_SIZE = 64;

	public HMAC(SHA1 hash) {
		this.hash = hash;
	}

	public byte[] hmac(byte[] key, byte[] msg) {
		if (key.length > BLOCK_SIZE)
			key = hash.hash(key);
		if (key.length < BLOCK_SIZE)
			key = Arrays.copyOf(key, BLOCK_SIZE);
		byte[] oKeyPad = new byte[BLOCK_SIZE];
		Arrays.fill(oKeyPad, (byte) 0x5c);
		oKeyPad = Encryption.repeatingXOR(oKeyPad, key);
		byte[] iKeyPad = new byte[BLOCK_SIZE];
		Arrays.fill(iKeyPad, (byte) 0x36);
		iKeyPad = Encryption.repeatingXOR(iKeyPad, key);
		return hash.hash(Utils.concat(oKeyPad,
				hash.hash(Utils.concat(iKeyPad, msg))));
	}
}
