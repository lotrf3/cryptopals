package cryptopals;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Challenges {
	class C12Server implements WebServer {

		@Override
		public byte[] decrypt(byte[] data) throws Exception {
			return null;
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			String append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n"
					+ "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n"
					+ "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n"
					+ "YnkK";
			byte[] app = DatatypeConverter.parseBase64Binary(append);
			byte[] pad = Arrays.copyOf(data, data.length + app.length);
			System.arraycopy(app, 0, pad, data.length, app.length);
			return encryptECB(pad, randomKey);
		}

	}

	class C14Server implements WebServer {

		@Override
		public byte[] decrypt(byte[] data) throws Exception {
			return null;
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			String append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n"
					+ "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n"
					+ "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n"
					+ "YnkK";
			int prefixSize = random.nextInt(16);
			byte[] prefix = new byte[prefixSize];
			random.nextBytes(prefix);
			byte[] postfix = DatatypeConverter.parseBase64Binary(append);
			byte[] res = new byte[prefixSize + data.length + postfix.length];
			System.arraycopy(prefix, 0, res, 0, prefixSize);
			System.arraycopy(data, 0, res, prefixSize, data.length);
			System.arraycopy(postfix, 0, res, prefixSize + data.length,
					postfix.length);
			return encryptECB(res, randomKey);
		}

	}

	class C16Server implements WebServer {

		public byte[] decrypt(byte[] data) throws Exception {
			data = decryptCBC(data, randomKey, randomKey);
			String str = new String(data);
			return parseKeyValueSet(str, ";", "=").get("userdata").getBytes();
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			byte[] pre = "comment1=cooking%20MC;userdata=".getBytes();
			byte[] post = ";comment2=%20like%20a%20pound%20of%20bacon"
					.getBytes();
			byte[] plaintxt = new byte[pre.length + data.length + post.length];
			System.arraycopy(pre, 0, plaintxt, 0, pre.length);
			System.arraycopy(data, 0, plaintxt, pre.length, data.length);
			System.arraycopy(post, 0, plaintxt, pre.length + data.length,
					post.length);
			return encryptCBC(plaintxt, randomKey, randomKey);
		}

		public byte[] encrypt(String str) throws Exception {
			str = sanitizeQueryParam(str);
			return encrypt(str.getBytes());
		}

		public boolean isAdmin(byte[] data) throws Exception {
			data = decryptCBC(data, randomKey, randomKey);
			String str = new String(data);
			return "true".equals(parseKeyValueSet(str, ";", "=").get("admin"));
		}

	}

	class C17Server implements WebServer {

		@Override
		public byte[] decrypt(byte[] data) throws Exception {
			data = decryptCBC(data, randomKey, randomIV);
			data = unpad(data);
			throw new GeneralSecurityException();
		}

		public byte[] encrypt() throws Exception {
			String[] strs = {
					"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
					"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
					"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
					"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
					"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
					"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
					"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
					"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
					"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
					"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" };
			int index = random.nextInt(strs.length);
			index = 0;
			return encrypt(DatatypeConverter.parseBase64Binary(strs[index]));
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			return encryptCBC(data, randomKey, randomIV);
		}
	}

	public static Map<Character, Double> freq = frequencyEnglish();

	static Challenges instance = new Challenges();

	private static String marker64 = "ABCDEFGHIJKLMNOPQRSTUVWXWZabcdefghijklmnopqrstuvwxyz0123456789+/";

	static SecureRandom random = new SecureRandom();

	static byte[] randomIV = new byte[] { 4, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
			12, 13, 14, 15, 16 };

	private static byte[] randomKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9,
			10, 11, 12, 13, 14, 15, 16 };

	public static void attackECBProfile() throws Exception {

		// TODO generalize for any order
		byte[] inj = createEncryptedProfile("fo@bar.comadmin\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b");
		byte[] enc = createEncryptedProfile("foooo@bar.com");
		System.arraycopy(inj, 16, enc, 32, 16);

		System.out.println(isEncryptedProfileAdmin(enc));
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
						print(decrypted);
						break;
					}
				}
			}
		}
		return decrypted;
	}

	public static void C5() {
		String enc = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
		String key = "ICE";

		System.out.println(DatatypeConverter.printHexBinary(repeatingXOR(
				enc.getBytes(), key.getBytes())));
	}

	public static void C6() throws IOException {
		String pathStr = "6.txt";
		Path path = Paths.get(pathStr);
		byte[] data = Files.readAllBytes(path);
		data = DatatypeConverter.parseBase64Binary(new String(data));
		int keysize = guessKeySize(data);
		byte[] key = repeatingXORdecode(data, keysize);
		byte[] decoded = repeatingXOR(data, key);
		System.out.print(new String(decoded));
		System.out.println();

	}

	public static void C7() throws Exception {

		String pathStr = "7.txt";
		String key = "YELLOW SUBMARINE";
		Path path = Paths.get(pathStr);
		byte[] data = Files.readAllBytes(path);
		data = DatatypeConverter.parseBase64Binary(new String(data));
		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
		byte[] decrypted = aes.doFinal(data);

		System.out.println(new String(decrypted));
	}

	public static void C8() throws Exception {

		String pathStr = "8.txt";
		BufferedReader br = new BufferedReader(new FileReader(pathStr));
		int i = 0;
		while (true) {
			i++;
			String line = br.readLine();
			if (line == null)
				break;
			byte[] data = DatatypeConverter.parseHexBinary(line);
			if (detectECB(data))
				System.out.println(i + ":" + line);
		}
		br.close();
	}

	public static void C9() throws Exception {
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 16)));
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 20)));
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 8)));
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 6)));
	}

	public static void C10() throws Exception {
		byte[] key = "YELLOW SUBMARINE".getBytes();
		byte[] iv = DatatypeConverter
				.parseHexBinary("00000000000000000000000000000000");
		Path path = Paths.get("10b.txt");
		byte[] data = Files.readAllBytes(path);
		data = DatatypeConverter.parseBase64Binary(new String(data));
		Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
				new IvParameterSpec(iv));
		byte[] decrypted = aes.doFinal(data);
		print(DatatypeConverter.printBase64Binary(decrypted));

		print(DatatypeConverter.printBase64Binary(encryptCBC(pad(data, 128),
				key, iv)));

	}

	public static void C11() throws Exception {
		String str = "Yellow SubmarineYellow SubmarineYellow SubmarineYellow SubmarineYellow Submarine";
		for (int i = 0; i < 100; i++) {
			print(detectBlockPattern(randomEncryption(str.getBytes()), 16, 3) ? "ECB"
					: "CBC");
		}
	}

	public static void C13() throws Exception {
		attackECBProfile();
	}

	public static byte[] createEncryptedProfile(String email) throws Exception {
		return encryptECB(printKeyValueSet(profileFor(email)).getBytes(),
				randomKey);
	}

	public static byte[] decryptCBC(byte[] data, byte[] key, byte[] iv)
			throws Exception {

		int blockSize = iv.length;
		byte[] res = decryptECB(data, key);
		// print(res);
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

	public static byte[] generateKey(int keysize) {
		byte key[] = new byte[keysize];
		random.nextBytes(key);
		return key;
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

	public static boolean isEncryptedProfileAdmin(byte[] data) throws Exception {
		Map<String, String> map = parseKeyValueSet(new String(decryptECB(data,
				randomKey)));
		return "admin".equals(map.get("role"));

	}

	public static void main(String[] args) throws Exception {
		instance.C17();
	}

	public static byte[] pad(byte[] data, int blockSize) {
		int padding = blockSize - (data.length % blockSize);
		byte[] padded = Arrays.copyOf(data, data.length + padding);
		Arrays.fill(padded, data.length, data.length + padding, (byte) padding);
		return padded;
	}

	public static Map<String, String> parseKeyValueSet(String str) {
		return parseKeyValueSet(str, "&", "=");
	}

	public static Map<String, String> parseKeyValueSet(String str,
			String separator, String equals) {
		Map<String, String> map = new LinkedHashMap<String, String>();
		String[] pairs = str.split(separator);
		for (String pair : pairs) {
			String[] x = pair.split(equals);
			map.put(x[0], x[1]);
		}
		return map;
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

	public static void print(byte data) {
		System.out.print((char) data);

	}

	public static void print(byte[] data) {
		System.out.println(new String(data));
	}

	private static void print(String str) {
		System.out.println(str);
	}

	public static String printKeyValueSet(Map<String, String> map) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> pair : map.entrySet())
			sb.append(pair.getKey()).append('=').append(pair.getValue())
					.append('&');
		sb.deleteCharAt(sb.length() - 1);
		return sb.toString();
	}

	public static Map<String, String> profileFor(String email) throws Exception {
		Map<String, String> map = new LinkedHashMap<String, String>();
		map.put("email", sanitizeQueryParam(email));
		map.put("uid", "10");
		map.put("role", "user");
		return map;
	}

	public static byte[] randomEncryption(byte[] data) throws Exception {
		int bytesPre = random.nextInt(5) + 5;
		int bytesPost = random.nextInt(5) + 5;
		byte[] pre = generateKey(bytesPre);
		byte[] post = generateKey(bytesPost);
		byte[] padded = new byte[data.length + bytesPre + bytesPost];
		System.arraycopy(pre, 0, padded, 0, bytesPre);
		System.arraycopy(data, 0, padded, bytesPre, data.length);
		System.arraycopy(post, 0, padded, bytesPre + data.length, bytesPost);
		if (random.nextBoolean()) {
			padded = encryptECB(padded, generateKey(16));
			System.out.print("ECB-");
		} else {
			padded = encryptCBC(padded, generateKey(16), generateKey(16));
			System.out.print("CBC-");
		}
		return padded;
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

	public static byte[] repeatingXORdecode(byte[] data, int keysize) {
		byte[][] transposed = new byte[keysize][data.length / keysize];
		for (int i = 0; i < transposed.length; i++)
			for (int j = 0; j < transposed[i].length; j++)
				if (i + j * keysize < data.length)
					transposed[i][j] = data[i + j * keysize];

		byte[] key = new byte[keysize];
		for (int i = 0; i < transposed.length; i++) {
			key[i] = (byte) xorDecodeSingleByteKey(transposed[i]);
		}

		return key;
	}

	public static String sanitizeQueryParam(String str) {
		return str.replace("&", "%26").replace("=", "%3D").replace(";", "%3A");
	}

	public static byte[] unpad(byte[] data) throws BadPaddingException {
		int padding = data[data.length - 1];
		if (padding < 0)
			padding += 256;
		for (int i = 1; i < padding; i++) {
			if (data[data.length - i - 1] != padding)
				throw new BadPaddingException();
		}
		byte[] unpadded = Arrays.copyOf(data, data.length - padding);
		return unpadded;
	}

	public static char xorDecodeSingleByteKey(byte[] b1) {
		char maxChar = 0;
		double max = 0;
		byte[] b3 = new byte[b1.length];
		for (char b2 = 0; b2 < 255; b2++) {
			double score = 0;
			for (int i = 0; i < b1.length; i++)
				b3[i] = (byte) (b1[i] ^ b2);
			String x = new String(b3);
			for (int i = 0; i < x.length(); i++) {
				Double s = freq.get(x.charAt(i));
				if (s != null)
					score += s;
			}
			if (score > max) {
				max = score;
				maxChar = b2;
			}
		}
		return maxChar;
	}

	private void alterRandomByte(byte[] data, int offset, int length) {
		int b = random.nextInt(length) + offset;
		data[b] = (byte) random.nextInt();
	}

	public byte[] attackCBCPaddingOracle(C17Server s) throws Exception {
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
				print(decrypted);
			}
		}
		return decrypted;
	}

	public void C12() throws Exception {
		print(plaintextAttackECB(new C12Server()));
	}

	public void C14() throws Exception {
		attackGeneralECB(new C14Server());
	}

	public void C15() throws Exception {
		// throws exception
		unpad("\u0001\u0002".getBytes());
	}

	public void C16() throws Exception {
		C16Server s = new C16Server();
		byte[] injection = injectBitflippingCBC(s,
				"aaaaa;admin=true".getBytes(), new TestAttack() {

					@Override
					public boolean test(WebServer s, byte[] injection)
							throws Exception {

						return ((C16Server) s).isAdmin(injection);
					}
				});
		if (s.isAdmin(injection))
			print("Success");
		else
			print(decryptCBC(injection, randomKey, randomKey));

	}

	public void C17() throws Exception {
		C17Server s = new C17Server();
		print(attackCBCPaddingOracle(s));

	}

	public byte[] injectBitflippingCBC(WebServer s, byte[] payload,
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

				repeatingXOR(pp, 0, pp.length, cipher, blockSize - pp.length,
						pp.length, injCipher, inOffset, pp.length);
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