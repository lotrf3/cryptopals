package cryptopals;

import static cryptopals.Analysis.detectBlockPattern;
import static cryptopals.Analysis.detectECBBlockSize;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.xml.bind.DatatypeConverter;

import cryptopals.Challenges.C17Server;

public class Analysis {
	private static SecureRandom random = new SecureRandom();
	private static String marker64 = "ABCDEFGHIJKLMNOPQRSTUVWXWZabcdefghijklmnopqrstuvwxyz0123456789+/";

	public static void alterRandomByte(byte[] data, int offset, int length) {
		int b = random.nextInt(length) + offset;
		data[b] = (byte) random.nextInt();
	}

	public static byte[] plaintextAttackECB(WebServer server) throws Exception {
		int blockSize = detectECBBlockSize(server);
		String str = "Yellow SubmarineYellow SubmarineYellow SubmarineYellow SubmarineYellow Submarine";
		if (!detectBlockPattern(server.encrypt(str.getBytes()), blockSize, 3))
			return null;
		int length = server.encrypt(new byte[0]).length;
		byte[] decrypted = new byte[length];
		for (int i = 0; i * blockSize < length; i++) {
			byte[] guess = new byte[(i + 1) * blockSize];
			for (int j = 0; j < blockSize; j++) {
				System.arraycopy(decrypted, 0, guess, blockSize - j - 1, j + i
						* blockSize);
				byte[] data;
				if (i >= 1)
					data = Arrays.copyOfRange(decrypted, (i - 1) * blockSize
							+ j + 1, i * blockSize);
				else
					data = new byte[(i + 1) * blockSize - j - 1];
				byte[] ciphertxt = server.encrypt(data);
				// construct dict
				for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
					guess[(i + 1) * blockSize - 1] = (byte) k;
					byte[] res = server.encrypt(guess);
					if (ArrayUtils.equals(res, i * blockSize, ciphertxt, i
							* blockSize, blockSize)) {
						decrypted[j + i * blockSize] = (byte) k;
						break;
					}
				}
			}
		}
		return decrypted;
	}

	public static byte[] attackCBCPaddingOracle(C17Server s) throws Exception {
		byte[] ciphertxt = s.encrypt();
		byte[] decrypted = new byte[ciphertxt.length];
		byte[] intermediate = new byte[ciphertxt.length];
		int blockSize = 16;
		for (int i = blockSize; i < ciphertxt.length; i += blockSize) {
			byte[] guess = new byte[i + blockSize];
			for (int j = 0; j < blockSize; j++) {
				int padding = j + 1;
				for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
					try {
						System.arraycopy(ciphertxt, i, guess, i, blockSize);
						guess[i - j - 1] = (byte) k;
						for (int l = j - 1; l >= 0; l--) {
							guess[i - l - 1] = (byte) (intermediate[i
									+ blockSize - l - 1] ^ padding);
						}
						s.decrypt(guess);
					} catch (BadPaddingException bpex) {
						// swallow padding error and retry
					} catch (Exception ex) {
						intermediate[i + blockSize - j - 1] = (byte) (k ^ padding + 1);
						decrypted[i + blockSize - j - 1] = (byte) (k ^ padding ^ ciphertxt[i
								- j - 1] + 1);
						break;
					}
				}
			}
		}
		return decrypted;
	}

	public static byte[] attackGeneralECB(WebServer server) throws Exception {
		int blockSize = detectECBBlockSize(server);
		String mark = marker64.substring(0, blockSize);
		String mark5rep = mark + mark + mark + mark + mark;
		if (!detectBlockPattern(server.encrypt(mark5rep.getBytes()), blockSize,
				3))
			return null;
		byte[] marker = new byte[blockSize];
		int length = -1;
		while (length == -1) {
			length = getMarkerAndLength(server.encrypt(mark5rep.getBytes()),
					blockSize, 5, marker);
		}
		byte[] decrypted = new byte[length];
		byte[][] test = new byte[blockSize][];
		// test[i]: [MARKER,GUESS,GUESS,...,GUESS,KNOWN_X]
		int C256 = (Byte.MAX_VALUE - Byte.MIN_VALUE + 1);
		for (int i = 0; i < blockSize; i++) {
			test[i] = new byte[blockSize + C256 * blockSize
					+ (blockSize - i - 1)];
			System.arraycopy(mark.getBytes(), 0, test[i], 0, blockSize);
		}
		for (int i = 0; i * blockSize < length; i++) {
			for (int j = 0; j < blockSize; j++) {
				// construct dict
				for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
					int kIndex = (k - Byte.MIN_VALUE + 1) * blockSize;
					if (i > 0)
						System.arraycopy(decrypted,
								(i - 1) * blockSize + j + 1, test[j], kIndex,
								blockSize);
					else
						System.arraycopy(decrypted, 0, test[j], kIndex
								+ blockSize - j - 1, j);
					test[j][kIndex + blockSize - 1] = (byte) k;
				}

				byte[] ciphertxt = null;
				int index = -1;
				while (index == -1) {
					ciphertxt = server.encrypt(test[j]);
					index = ArrayUtils.containsBlock(ciphertxt, marker,
							blockSize);
				}
				for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
					int kIndex = (k - Byte.MIN_VALUE + 1) * blockSize;
					if (ArrayUtils.equals(ciphertxt, index + kIndex, ciphertxt,
							index + (i + C256 + 1) * blockSize, blockSize)) {
						decrypted[i * blockSize + j] = (byte) k;
						break;
					}
				}
			}
		}
		return decrypted;
	}

	// returns [padding needed to reach boundary, index of block]
	public static int[] detectBlockBoundary(WebServer server, int blockSize)
			throws Exception {
		byte[] marker = marker64.substring(0, blockSize).getBytes();
		byte[] a = server.encrypt(marker);
		marker[0] = (byte) (marker[0] ^ 0xFF);
		byte[] b = server.encrypt(marker);
		int index = ArrayUtils.firstNonEqualByte(a, b);
		marker[0] = (byte) (marker[0] ^ 0xFF);
		for (int i = 1; i < blockSize; i++) {
			marker[i] = (byte) (marker[i] ^ 0xFF);
			b = server.encrypt(marker);
			int x = ArrayUtils.firstNonEqualByte(a, b);
			if (index != x)
				return new int[] { i, x };
			marker[i] = (byte) (marker[i] ^ 0xFF);
		}
		return new int[] { 0, index };

	}

	public static boolean detectBlockPattern(byte[] data, int blockSize,
			int threshold) {
		HashMap<String, Integer> counter = new HashMap<String, Integer>();
		for (int i = 0; i < data.length; i += blockSize) {
			String str = DatatypeConverter.printBase64Binary(Arrays
					.copyOfRange(data, i, i + blockSize));
			Integer count = counter.get(str);
			if (count == null)
				counter.put(str, 1);
			else if (count + 1 < threshold)
				counter.put(str, count + 1);
			else
				return true;
		}
		return false;
	}

	public static boolean detectECB(byte[] data) {
		Map<Byte, Integer> counter = new HashMap<Byte, Integer>();
		for (int i = 0; i < data.length; i++) {
			Integer count = counter.get(data[i]);
			if (count == null)
				count = 1;
			else
				count++;
			counter.put(data[i], count);
		}
		int max = 0;
		for (byte b : counter.keySet())
			if (counter.get(b) > max)
				max = counter.get(b);
		double ratio = max / (double) data.length;
		return ratio > 0.04;// TODO fine tune?
	}

	public static int detectECBBlockSize(WebServer server) throws Exception {
		int length = server.encrypt(new byte[0]).length;
		for (int i = 1; i < 128; i++) {
			int x = server.encrypt(new byte[i]).length;
			if (x != length)
				return 160 - 144;
		}
		return -1;

	}

	public static int getMarkerAndLength(byte[] data, int blockSize,
			int threshold, byte[] mark) {
		HashMap<String, Integer> counter = new HashMap<String, Integer>();
		for (int i = 0; i < data.length; i += blockSize) {
			System.arraycopy(data, i, mark, 0, blockSize);
			String str = DatatypeConverter.printBase64Binary(mark);
			Integer count = counter.get(str);
			if (count == null)
				counter.put(str, 1);
			else if (count + 1 < threshold)
				counter.put(str, count + 1);
			else
				return data.length - i - blockSize;
		}
		return -1;
	}

	public static int guessKeySize(byte[] data) {
		double min = Double.POSITIVE_INFINITY;
		int keysize = 0;
		for (int k = 2; k < 40; k++) {
			double total = 0;
			int blocksCount = data.length / k - 1;
			for (int i = 0; i < blocksCount; i++) {
				long dist = hammingDist(data, i * k, data, (i + 1) * k, k);
				total += dist / (double) k;
			}
			double avg = total / blocksCount;
			if (avg < min) {
				min = avg;
				keysize = k;
			}
		}
		return keysize;
	}

	public static long hammingDist(byte[] a, byte[] b) {
		return hammingDist(a, 0, b, 0, Math.min(a.length, b.length));
	}

	public static long hammingDist(byte[] a, int aOffset, byte[] b,
			int bOffset, int length) {
		long count = 0;
		for (int i = 0; i < length; i++) {
			byte diff = (byte) (a[i + aOffset] ^ b[i + bOffset]);
			for (int j = 0; j < 8; j++) {
				if ((diff & 0x01) != 0)
					count++;
				diff = (byte) (diff >> 1);
			}
		}
		return count;

	}

	public static byte[] injectBitflippingCBC(WebServer s, byte[] payload,
			TestAttack test) throws Exception {
		int padding = 0, outOffset = 0, blockSize = 16;// How to detect this in
		// CBC?
		int payloadPadding = blockSize - payload.length;
		if (payloadPadding < 0)
			throw new Exception(
					"Injection payload must be within the block size of "
							+ blockSize);
		byte[] pp = new byte[blockSize];
		System.arraycopy(marker64.substring(0, payloadPadding).getBytes(), 0,
				pp, 0, payloadPadding);
		System.arraycopy(payload, 0, pp, payloadPadding, payload.length);

		String marker = marker64.substring(0, blockSize);
		// pad to block boundary
		int[] blockRes = detectBlockBoundary(s, blockSize);
		padding = blockRes[0];
		String plaintxt = marker.substring(0, padding) + marker + marker;
		// String plaintxt = "=" + marker + marker;
		byte[] plainbytes = plaintxt.getBytes();
		while (true) {
			try {
				byte[] enc = s.encrypt(plainbytes);
				byte[] injCipher = Arrays.copyOf(enc, enc.length);
				byte[] cipher = new byte[blockSize];
				int inOffset = blockRes[1];
				outOffset = ArrayUtils.indexOf(s.decrypt(enc), plainbytes)
						+ padding + blockSize;
				for (int i = 0; i < blockSize; i++) {
					for (int j = Byte.MIN_VALUE; j <= Byte.MAX_VALUE; j++) {
						try {
							injCipher[i + inOffset] = (byte) j;
							byte[] result = s.decrypt(injCipher);
							int y = i + outOffset;
							byte x = result[y];
							cipher[i] = (byte) (x ^ j);
							System.arraycopy(enc, 0, injCipher, 0, enc.length);
							break;

						} catch (Exception e) {
							// swallow server errors
						}
					}
				}

				Encryption.repeatingXOR(pp, 0, pp.length, cipher, blockSize
						- pp.length, pp.length, injCipher, inOffset, pp.length);
				s.decrypt(injCipher);
				if (test != null && !test.test(s, injCipher))
					throw new Exception();
				return injCipher;
			} catch (Exception e) {

				alterRandomByte(plainbytes, padding, blockSize);
				// swallow more errors
				System.out.println("hithar");
			}
		}
	}
}