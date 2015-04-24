package cryptopals;

import static cryptopals.Encryption.*;
import static cryptopals.Analysis.*;
import static cryptopals.Utils.print;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

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
			int blockSize = 16;
			byte[] iv = Arrays.copyOfRange(data, 0, blockSize);
			byte[] ciphertxt = Arrays.copyOfRange(data, blockSize, data.length);
			data = decryptCBC(ciphertxt, randomKey, iv);
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
			return encrypt(DatatypeConverter.parseBase64Binary(strs[index]));
		}

		// prepends IV to ciphertxt
		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			return Utils
					.concat(randomIV, encryptCBC(data, randomKey, randomIV));
		}
	}

	class C19Server implements WebServer {
		private CTR ctr = new CTR(randomKey, randomIV);

		private String[] strs = {
				"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
				"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
				"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
				"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
				"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
				"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
				"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
				"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
				"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
				"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
				"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
				"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
				"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
				"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
				"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
				"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
				"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
				"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
				"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
				"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
				"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
				"U2hlIHJvZGUgdG8gaGFycmllcnM/",
				"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
				"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
				"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
				"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
				"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
				"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
				"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
				"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
				"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
				"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
				"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
				"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
				"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
				"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
				"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
				"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=" };

		@Override
		public byte[] decrypt(byte[] data) throws Exception {
			return ctr.decrypt(data);
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			return ctr.encrypt(data);
		}

		public byte[][] encrypt() throws Exception {
			byte[][] res = new byte[strs.length][];
			for (int i = 0; i < strs.length; i++)
				res[i] = encrypt(DatatypeConverter.parseBase64Binary(strs[i]));
			return res;
		}

	}

	class C24Server implements WebServer {

		SecureRandom r2;
		Random r1;
		public RandomStreamCipher16 rsc;

		public C24Server() {
			r2 = new SecureRandom();
			r1 = new MT19937(0);
			rsc = new RandomStreamCipher16(r1);
			rsc.setSeed(r2.nextInt());

		}

		@Override
		public byte[] decrypt(byte[] data) throws Exception {
			return rsc.decrypt(data);
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			byte[] prefix = new byte[r2.nextInt(1000)];
			r2.nextBytes(prefix);
			byte[] cpy = Arrays.copyOf(prefix, prefix.length + data.length);
			System.arraycopy(data, 0, cpy, prefix.length, data.length);
			return rsc.encrypt(cpy);
		}

	}

	class C25Server implements WebServer {

		CTR ctr = new CTR(randomIV, randomKey);

		@Override
		public byte[] decrypt(byte[] data) throws Exception {
			return ctr.decrypt(data);
		}

		@Override
		public byte[] encrypt(byte[] data) throws Exception {
			return ctr.encrypt(data);
		}

		public byte[] edit(byte[] ciphertxt, int offset, byte[] newtxt)
				throws Exception {
			byte[] plaintxt = ctr.decrypt(ciphertxt);
			System.arraycopy(newtxt, 0, plaintxt, offset, newtxt.length);
			return ctr.encrypt(plaintxt);
		}

	}

	class C26Server implements WebServer {

		CTR ctr = new CTR(randomIV, randomKey);

		public byte[] decrypt(byte[] data) throws Exception {
			data = ctr.decrypt(data);
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
			return ctr.encrypt(plaintxt);
		}

		public byte[] encrypt(String str) throws Exception {
			str = sanitizeQueryParam(str);
			return encrypt(str.getBytes());
		}

		public boolean isAdmin(byte[] data) throws Exception {
			data = ctr.decrypt(data);
			String str = new String(data);
			return "true".equals(parseKeyValueSet(str, ";", "=").get("admin"));
		}

	}

	class C27Server implements WebServer {

		public byte[] decrypt(byte[] data) throws Exception {
			data = decryptCBC(data, randomKey, randomKey);
			for (int i = 0; i < data.length; i++)
				if (!Utils.isValidASCII(data[i]))
					throw new IllegalArgumentException(
							"This is not valid ASCII:" + new String(data));
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

	class C29Server implements WebServer {

		SHA1 sha1 = new SHA1();
		byte[] randomKey = generateKey(random.nextInt(100) + 5);

		public byte[] decrypt(byte[] data) {
			return null;
		}

		@Override
		public byte[] encrypt(byte[] data) {
			return sha1.hash(Utils.concat(randomKey, data));
		}

		public boolean verify(byte[] data, byte[] mac) {
			return Utils.equals(encrypt(data), mac);
		}

	}

	class C30Server implements WebServer {

		MD4 md4 = new MD4();

		// byte[] randomKey = generateKey(random.nextInt(100) + 5);

		public byte[] decrypt(byte[] data) {
			return null;
		}

		@Override
		public byte[] encrypt(byte[] data) {
			return md4.digest(Utils.concat(randomKey, data));
		}

		public boolean verify(byte[] data, byte[] mac) {
			return Utils.equals(encrypt(data), mac);
		}

	}

	class C31Server implements WebServer {

		SHA1 sha1 = new SHA1();
		HMAC hmac = new HMAC(sha1);

		// byte[] randomKey = generateKey(random.nextInt(100) + 5);

		public byte[] decrypt(byte[] data) {
			return null;
		}

		@Override
		public byte[] encrypt(byte[] data) {
			return hmac.hmac(randomKey, data);
		}

		public boolean verify(byte[] data, byte[] mac) throws Exception {
			byte[] macAuth = hmac.hmac(randomKey, data);
			return insecureCompare(macAuth,mac);
		}

		private boolean insecureCompare(byte[] mac1, byte[] mac2) throws Exception {
			for (int i = 0; i < mac1.length; i++) {
				if (mac1[i] != mac2[i])
					return false;
				Thread.sleep(5);
			}
			return true;
		}

	}

	static Challenges instance = new Challenges();

	static SecureRandom random = new SecureRandom();

	static byte[] randomIV = new byte[] {
			4,
			2,
			3,
			4,
			5,
			6,
			7,
			8,
			9,
			10,
			11,
			12,
			13,
			14,
			15,
			16 };

	private static byte[] randomKey = new byte[] {
			1,
			2,
			3,
			4,
			5,
			6,
			7,
			8,
			9,
			10,
			11,
			12,
			13,
			14,
			15,
			16 };

	public static void attackECBProfile() throws Exception {

		// TODO generalize for any order
		byte[] inj = createEncryptedProfile("fo@bar.comadmin\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b");
		byte[] enc = createEncryptedProfile("foooo@bar.com");
		System.arraycopy(inj, 16, enc, 32, 16);

		System.out.println(isEncryptedProfileAdmin(enc));
	}

	public void C1() {
		String hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
		String out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
		String b64 = DatatypeConverter.printBase64Binary(DatatypeConverter
				.parseHexBinary(hex));
		System.out.println(b64);
		System.out.println(out);
	}

	public void C2() {

		String p1 = "1c0111001f010100061a024b53535009181c";
		String p2 = "686974207468652062756c6c277320657965";
		String out = "746865206b696420646f6e277420706c6179";
		byte[] b1 = DatatypeConverter.parseHexBinary(p1);
		byte[] b2 = DatatypeConverter.parseHexBinary(p2);
		byte[] b3 = new byte[b1.length];
		for (int i = 0; i < b1.length; i++)
			b3[i] = (byte) (b1[i] ^ b2[i]);
		System.out.println(DatatypeConverter.printHexBinary(b3));
		System.out.println(out);
	}

	public void C3() {

		byte[] b1 = DatatypeConverter
				.parseHexBinary("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
		Map<Character, Double> freq = frequencyEnglish();
		byte maxByte = 0;
		double max = 0;
		String maxString = "";
		byte[] b3 = new byte[b1.length];
		for (byte b2 = 0; b2 >= 0; b2++) {
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
				maxByte = b2;
				maxString = x;
			}
		}
		for (int i = 0; i < b1.length; i++)
			b3[i] = (byte) (b1[i] ^ maxByte);

		System.out.println("~~~~~~~~~~~~");
		System.out.println(maxString);
		System.out.println(DatatypeConverter.printHexBinary(b3));
		System.out.println(maxByte);

	}

	public void C4() throws Exception {
		BufferedReader br = new BufferedReader(new FileReader("4.txt"));

		Map<Character, Double> freq = frequencyEnglish();
		byte maxByte = 0;
		double max = 0;
		String maxString = "";
		while (true) {
			String line = br.readLine();
			if (line == null)
				break;
			byte[] b1 = DatatypeConverter.parseHexBinary(line);
			byte[] b3 = new byte[b1.length];
			for (byte b2 = 0; b2 >= 0; b2++) {
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
					maxByte = b2;
					maxString = x;
				}
			}
		}

		System.out.println("~~~~~~~~~~~~");
		System.out.println(maxString);
		System.out.println(maxByte);
		br.close();

	}

	public void C5() {
		String enc = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
		String key = "ICE";

		System.out.println(DatatypeConverter.printHexBinary(repeatingXOR(
				enc.getBytes(), key.getBytes())));
	}

	public void C6() throws IOException {
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

	public void C7() throws Exception {

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

	public void C8() throws Exception {

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

	public void C9() throws Exception {
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 16)));
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 20)));
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 8)));
		System.out.println(new String(pad("YELLOW SUBMARINE".getBytes(), 6)));
	}

	public void C10() throws Exception {
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

	public void C11() throws Exception {
		String str = "Yellow SubmarineYellow SubmarineYellow SubmarineYellow SubmarineYellow Submarine";
		for (int i = 0; i < 100; i++) {
			print(detectBlockPattern(randomEncryption(str.getBytes()), 16, 3) ? "ECB"
					: "CBC");
		}
	}

	public void C12() throws Exception {
		print(plaintextAttackECB(new C12Server()));
	}

	public void C13() throws Exception {
		attackECBProfile();
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
		byte[] injection = Analysis.injectBitflippingCBC(s,
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
		HashSet<String> set = new HashSet<String>();
		for (int i = 0; i < 10; i++)
			if (set.add(new String(attackCBCPaddingOracle(s))))
				i = 0;
		print(set.toString());

	}

	public void C18() throws Exception {
		CTR ctr = new CTR(new byte[16], "YELLOW SUBMARINE".getBytes());
		byte[] ciphertxt = DatatypeConverter
				.parseBase64Binary("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
		print(ctr.decrypt(ciphertxt));
	}

	public void C19() throws Exception {
		C19Server s = new C19Server();
		byte[][] ciphertxts = s.encrypt();
		byte[] keystream = Analysis.attackSingleNonceCTR(ciphertxts);
		for (int i = 0; i < ciphertxts.length; i++)
			print(Encryption.repeatingXOR(keystream, ciphertxts[i]));
	}

	public void C20() throws Exception {
		BufferedReader br = new BufferedReader(new FileReader("20.txt"));
		CTR ctr = new CTR(randomKey, randomIV);
		byte[][] ciphertxts = new byte[(int) br.lines().count()][];
		br.close();
		br = new BufferedReader(new FileReader("20.txt"));
		for (int i = 0; i < ciphertxts.length; i++) {
			ciphertxts[i] = ctr.encrypt(DatatypeConverter.parseBase64Binary(br
					.readLine()));
		}
		br.close();
		byte[] keystream = Analysis.attackSingleNonceCTR(ciphertxts);
		for (int i = 0; i < ciphertxts.length; i++)
			print(Encryption.repeatingXOR(keystream, ciphertxts[i]));
	}

	public void C21() {
		MT19937 r = new MT19937(1);
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
		System.out.println(r.nextInt());
	}

	public void C22() throws Exception {
		int t1 = (int) System.currentTimeMillis();
		MT19937 r = new MT19937(t1);
		int rnd = r.nextInt();
		int t2 = t1 + r.nextInt(1000) + 4;
		int t1Copy = Analysis.findTimestampSeededRandMT19937(rnd, t2);
		System.out.print(t1 + " " + t1Copy);
	}

	public void C23() {
		MT19937 r1 = new MT19937(1);
		MT19937 r2 = Analysis.cloneRandMT19937(r1);
		System.out.println(r1.nextInt());
		System.out.println(r2.nextInt());
		System.out.println(r1.nextInt());
		System.out.println(r2.nextInt());
		System.out.println(r1.nextInt());
		System.out.println(r2.nextInt());
	}

	public void C24() throws Exception {
		print(bruteMT19937Cipher(new C24Server()));
	}

	public void C25() throws Exception {
		Path path = Paths.get("25.txt");
		byte[] data = Files.readAllBytes(path);
		data = DatatypeConverter.parseBase64Binary(new String(data));
		data = Encryption.decryptECB(data, "YELLOW SUBMARINE".getBytes());
		data = Encryption.unpad(data);
		C25Server s = new C25Server();
		byte[] ciphertxt = s.encrypt(data);
		print(Analysis.attackEditableCTR(ciphertxt, s));
	}

	public void C26() throws Exception {
		C26Server s = new C26Server();
		byte[] injection = injectBitflippingCTR(s, "a;admin=true".getBytes());

		if (s.isAdmin(injection))
			print("Success");

	}

	public void C27() throws Exception {
		C27Server s = new C27Server();
		print(Analysis.recoverCBCKeyIsIV(s, s.encrypt("asdf")));
		print(randomKey);
	}

	public void C28() throws Exception {
		SHA1 sha1 = new SHA1();

		print(sha1.hash(Utils.concat(randomKey, "test".getBytes())));
		print(sha1.hash(Utils.concat(randomKey, "test".getBytes())));
		print(sha1.hash(Utils.concat(randomKey, "tes1".getBytes())));
	}

	public void C29() throws Exception {
		byte[] msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
				.getBytes();
		byte[] payload = ";admin=true".getBytes();
		C29Server s = new C29Server();
		byte[] mac = s.encrypt(msg);
		AuthenticatedMessage inj = Analysis.forgeSHA1MAC(s, mac, msg, payload);
		print(inj.msg);
		System.out.println(s.verify(inj.msg, inj.mac));
	}

	public void C30() {

		byte[] msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
				.getBytes();

		byte[] payload = ";admin=true".getBytes();
		C30Server s = new C30Server();
		byte[] mac = s.encrypt(msg);
		AuthenticatedMessage inj = Analysis.forgeMD4MAC(s, mac, msg, payload);
		print(inj.msg);
		System.out.println(s.verify(inj.msg, inj.mac));

	}

	public void C31() throws Exception {
		C31Server s = new C31Server();
		print(Analysis.attackHMACTimingLeak(s, "hello".getBytes(),20));

	}

	public static byte[] createEncryptedProfile(String email) throws Exception {
		return encryptECB(printKeyValueSet(profileFor(email)).getBytes(),
				randomKey);
	}

	public static byte[] generateKey(int keysize) {
		byte key[] = new byte[keysize];
		random.nextBytes(key);
		return key;
	}

	public static boolean isEncryptedProfileAdmin(byte[] data) throws Exception {
		Map<String, String> map = parseKeyValueSet(new String(decryptECB(data,
				randomKey)));
		return "admin".equals(map.get("role"));

	}

	public static void main(String[] args) throws Exception {
		instance.C31();
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

}