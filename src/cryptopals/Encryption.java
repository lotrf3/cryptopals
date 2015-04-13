package cryptopals;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

	public static byte[] decryptCBC(byte[] data, byte[] key, byte[] iv)
			throws Exception {

		int blockSize = iv.length;
		byte[] res = decryptECB(data, key);
		int ivStart = 0;
		for (int i = 0; i < data.length; i += blockSize) {
			// print(res);
			repeatingXOR(res, i, blockSize, iv, ivStart, blockSize, res, i,
					blockSize);
			iv = data;
			ivStart = i;
		}
		return res;
	}

	public static byte[] decryptECB(byte[] data, byte[] key) throws Exception {
		Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
		aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
		byte[] decrypted = aes.doFinal(data);
		return decrypted;
	}

	public static byte[] encryptCBC(byte[] dec, byte[] key, byte[] iv)
			throws Exception {

		Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
				new IvParameterSpec(iv));
		return aes.doFinal(dec);
		// byte[] enc = new byte[dec.length];
		// return encryptCBC(dec, 0, key, iv, 0, enc, 0, 16);
	}

	public static byte[] encryptCBC(byte[] dec, int decOffset, byte[] key,
			byte[] iv, int ivOffset, byte[] enc, int encOffset, int blockSize)
			throws Exception {
		// TODO

		/*
		 * repeatingXOR(dec, decOffset, blockSize, iv, ivOffset, blockSize, enc,
		 * encOffset, blockSize); encryptECB(dec, decOffset, blockSize, key,
		 * enc, encOffset); if (decOffset + blockSize < dec.length)
		 * encryptCBC(dec, blockSize + decOffset, key, enc, encOffset, enc,
		 * blockSize + encOffset, blockSize);
		 */
		return enc;
	}

	public static byte[] encryptECB(byte[] data, byte[] key) throws Exception {
		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		byte[] encrypted = aes.doFinal(data);
		return encrypted;
	}

	public static byte[] encryptECB(byte[] dec, int decOffset, int length,
			byte[] key, byte[] enc, int encOffset) throws Exception {
		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		aes.doFinal(dec, decOffset, length, enc, encOffset);
		return enc;
	}

	public static byte[] repeatingXOR(byte[] enc, byte[] key) {
		return repeatingXOR(enc, 0, enc.length, key, 0, key.length, enc.length);
	}

	public static byte[] repeatingXOR(byte[] a, int aOffset, int aLength,
			byte[] b, int bOffset, int bLength, byte[] res, int resOffset,
			int resLength) {
		for (int i = 0; i < resLength; i++) {
			int ax = a[(i % aLength) + aOffset];
			int bx = b[(i % bLength) + bOffset];
			res[i + resOffset] = (byte) (ax ^ bx);
		}
		return res;
	}

	public static byte[] repeatingXOR(byte[] a, int aOffset, int aLength,
			byte[] b, int bOffset, int bLength, int resLength) {
		byte[] res = new byte[resLength];
		return repeatingXOR(a, aOffset, aLength, b, bOffset, bLength, res, 0,
				resLength);
	}

	public static byte[] pad(byte[] data, int blockSize) {
		int padding = blockSize - (data.length % blockSize);
		byte[] padded = Arrays.copyOf(data, data.length + padding);
		Arrays.fill(padded, data.length, data.length + padding, (byte) padding);
		return padded;
	}

	public static byte[] unpad(byte[] data) throws BadPaddingException {
		int padding = data[data.length - 1];
		if (padding <= 0)
			padding += 256;
		for (int i = 1; i < padding; i++) {
			if (data[data.length - i - 1] != padding)
				throw new BadPaddingException();
		}
		byte[] unpadded = Arrays.copyOf(data, data.length - padding);
		return unpadded;
	}

}
