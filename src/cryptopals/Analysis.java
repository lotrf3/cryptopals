package cryptopals;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.xml.bind.DatatypeConverter;

import cryptopals.Challenges.C17Server;
import cryptopals.Challenges.C25Server;

public class Analysis {
	public static Map<Character, Double> freq = frequencyEnglish();
	private static SecureRandom random = new SecureRandom();
	private static String marker64 = "ABCDEFGHIJKLMNOPQRSTUVWXWZabcdefghijklmnopqrstuvwxyz0123456789+/";

	public static byte[] injectBitflippingCTR(WebServer s, byte[] payload) throws Exception {
		byte[] knowntxt1 = marker64.substring(0, payload.length).getBytes();
		byte[] ciphertxt1 = s.encrypt(knowntxt1);
		byte[] knowntxt2 = marker64.substring(1, payload.length + 1).getBytes();
		byte[] ciphertxt2 = s.encrypt(knowntxt2);
		int offset = Utils.firstNonEqualByte(ciphertxt1, ciphertxt2);
		byte[] key = Encryption.repeatingXOR(ciphertxt1, offset,
				payload.length, knowntxt1, 0, payload.length, payload.length);
		byte[] cipherPayload = Encryption.repeatingXOR(key, payload);
		System.arraycopy(cipherPayload, 0, ciphertxt1, offset, payload.length);

		return ciphertxt1;
	}

	public static byte[] attackEditableCTR(byte[] ciphertxt, C25Server s)
			throws Exception {
		byte[] inj = new byte[ciphertxt.length];
		// Arrays.fill(inj, (byte)' ');
		byte[] alteredtxt = s.edit(ciphertxt, 0, inj);
		byte[] key = Encryption.repeatingXOR(alteredtxt, ciphertxt);
		return Encryption.repeatingXOR(key, inj);
	}

	public static byte[] bruteMT19937Cipher(WebServer s) throws Exception {
		byte[] mark = marker64.getBytes();
		byte[] ciphertxt = s.encrypt(mark);
		RandomStreamCipher16 rsc = new RandomStreamCipher16(new MT19937(0));
		for (int i = 0; i < rsc.MAX_KEY_SIZE; i++) {
			rsc.setSeed(i);
			byte[] cleartxt = rsc.decrypt(ciphertxt);
			if (Utils.indexOf(cleartxt, mark) != -1)
				return cleartxt;
		}
		return null;
	}

	public static byte[] injectionCloneMT19937Cipher(WebServer s)
			throws Exception {
		byte[] mark = new byte[624 * 4 * 2];
		byte[] ciphertxt = s.encrypt(mark);
		for (int i = 0; i < 4; i++) {
			IntBuffer intBuf = ByteBuffer.wrap(ciphertxt, i,
					ciphertxt.length - i).asIntBuffer();
			int[] ints = new int[intBuf.remaining()];
			intBuf.get(ints);
			int[] untempered = new int[ints.length];
			for (int j = 0; j < ints.length; j++)
				untempered[j] = untemperRandMT19937(ints[j]);
			int blockIndex;
			for (blockIndex = 0; blockIndex + 625 < untempered.length; blockIndex++) {
				MT19937 rand = new MT19937(Arrays.copyOfRange(untempered,
						blockIndex, blockIndex + 624));
				if (rand.nextInt() == ints[blockIndex + 624]) {
					// return new RandomStreamCipher(rand);
				}
			}
		}
		return null;
	}

	public static int findTimestampSeededRandMT19937(int rnd, int timestamp)
			throws Exception {
		for (int t = timestamp; t < 0; t--)
			if (new MT19937(t).nextInt() == rnd)
				return t;
		throw new Exception();
	}

	public static int untemperRandMT19937(int a) {
		int b = a ^ (a >>> 18);

		int c = b ^ ((b << 15) & 0xefc60000);

		int d = c;
		d = c ^ ((d << 7) & 0x9d2c5680);
		d = c ^ ((d << 7) & 0x9d2c5680);
		d = c ^ ((d << 7) & 0x9d2c5680);
		d = c ^ ((d << 7) & 0x9d2c5680);

		int y = d;
		y = d ^ (y >>> 11);
		y = d ^ (y >>> 11);
		return y;
	}

	public static MT19937 cloneRandMT19937(MT19937 rand) {
		int[] state = new int[624];
		for (int i = 0; i < 624; i++)
			state[i] = untemperRandMT19937(rand.nextInt());

		return new MT19937(state);

	}

	public static void alterRandomByte(byte[] data, int offset, int length) {
		int b = random.nextInt(length) + offset;
		data[b] = (byte) random.nextInt();
	}

	public static Map<Character, Double> frequencyEnglish() {
		HashMap<Character, Double> a = new HashMap<Character, Double>();
		a.put('a', 8.167);
		a.put('b', 1.492);
		a.put('c', 2.782);
		a.put('d', 4.253);
		a.put('e', 12.702);
		a.put('f', 2.228);
		a.put('g', 2.015);
		a.put('h', 6.094);
		a.put('i', 6.966);
		a.put('j', 0.153);
		a.put('k', 0.772);
		a.put('l', 4.025);
		a.put('m', 2.406);
		a.put('n', 6.749);
		a.put('o', 7.507);
		a.put('p', 1.929);
		a.put('q', 0.095);
		a.put('r', 5.987);
		a.put('s', 6.327);
		a.put('t', 9.056);
		a.put('u', 2.758);
		a.put('v', 0.978);
		a.put('w', 2.360);
		a.put('x', 0.150);
		a.put('y', 1.974);
		a.put('z', 0.074);
		a.put('A', 8.167);
		a.put('B', 1.492);
		a.put('C', 2.782);
		a.put('D', 4.253);
		a.put('E', 12.702);
		a.put('F', 2.228);
		a.put('G', 2.015);
		a.put('H', 6.094);
		a.put('I', 6.966);
		a.put('J', 0.153);
		a.put('K', 0.772);
		a.put('L', 4.025);
		a.put('M', 2.406);
		a.put('N', 6.749);
		a.put('O', 7.507);
		a.put('P', 1.929);
		a.put('Q', 0.095);
		a.put('R', 5.987);
		a.put('S', 6.327);
		a.put('T', 9.056);
		a.put('U', 2.758);
		a.put('V', 0.978);
		a.put('W', 2.360);
		a.put('X', 0.150);
		a.put('Y', 1.974);
		a.put('Z', 0.074);
		a.put(' ', 15.0);

		return a;
	}

	// returns keystream
	public static byte[] attackSingleNonceCTR(byte[][] ciphertxts) {
		// TODO can definitely improve statistics here
		int keystreamLength = 0;
		for (int i = 0; i < ciphertxts.length; i++)
			keystreamLength = Math.max(ciphertxts[i].length, keystreamLength);

		byte[] keystream = new byte[keystreamLength];
		for (int i = 0; i < keystreamLength; i++) {

			double maxScore = Double.NEGATIVE_INFINITY;
			for (int j = Byte.MIN_VALUE; j <= Byte.MAX_VALUE; j++) {
				double score = 0;
				for (int k = 0; k < ciphertxts.length; k++)
					if (i < ciphertxts[k].length) {
						Double d = freq.get((char) (j ^ ciphertxts[k][i]));
						if (d != null)
							score += d;
					}
				if (score > maxScore) {
					maxScore = score;
					keystream[i] = (byte) j;
				}
			}
		}

		return keystream;

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
					if (Utils.equals(res, i * blockSize, ciphertxt, i
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
		int blockSize = 16;
		byte[] ciphertxtWithIV = s.encrypt();
		byte[] ciphertxt = Arrays.copyOfRange(ciphertxtWithIV, blockSize,
				ciphertxtWithIV.length);
		byte[] decrypted = new byte[ciphertxt.length];
		byte[] intermediate = new byte[ciphertxt.length];
		for (int i = 0; i < ciphertxt.length; i += blockSize) {
			byte[] guess = new byte[i + blockSize * 2];
			for (int j = 0; j < blockSize; j++) {
				int padding = j + 1;
				for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
					try {
						System.arraycopy(ciphertxt, i, guess, blockSize + i,
								blockSize);
						guess[blockSize + i - j - 1] = (byte) k;
						for (int l = j - 1; l >= 0; l--) {
							guess[blockSize + i - l - 1] = (byte) (intermediate[i
									+ blockSize - l - 1] ^ padding);
						}
						s.decrypt(guess);
					} catch (BadPaddingException bpex) {
						// swallow padding error and retry
					} catch (Exception ex) {
						intermediate[i + blockSize - j - 1] = (byte) (k ^ padding);
						decrypted[i + blockSize - j - 1] = (byte) (k ^ padding ^ ciphertxtWithIV[blockSize
								+ i - j - 1]);
						break;
					}
				}
			}
		}
		return Encryption.unpad(decrypted);
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
					index = Utils.containsBlock(ciphertxt, marker, blockSize);
				}
				for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
					int kIndex = (k - Byte.MIN_VALUE + 1) * blockSize;
					if (Utils.equals(ciphertxt, index + kIndex, ciphertxt,
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
		int index = Utils.firstNonEqualByte(a, b);
		marker[0] = (byte) (marker[0] ^ 0xFF);
		for (int i = 1; i < blockSize; i++) {
			marker[i] = (byte) (marker[i] ^ 0xFF);
			b = server.encrypt(marker);
			int x = Utils.firstNonEqualByte(a, b);
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
				outOffset = Utils.indexOf(s.decrypt(enc), plainbytes) + padding
						+ blockSize;
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
