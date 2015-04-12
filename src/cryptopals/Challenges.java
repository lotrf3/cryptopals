package cryptopals;

import static cryptopals.Encryption.*;
import static cryptopals.Analysis.*;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
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
	
	public void C3(){

		byte[] b1 = DatatypeConverter.parseHexBinary("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
		Map<Character, Double> freq = frequencyEnglish();
		byte maxByte = 0;
		double max = 0;
		String maxString = "";
		byte[] b3 = new byte[b1.length];
		for(byte b2 = 0; b2 >= 0; b2++){
			double score = 0;
			for(int i=0; i<b1.length; i++)
				b3[i] =  (byte) (b1[i]^b2);
			String x = new String(b3);
			for(int i=0;i<x.length();i++){
				Double s = freq.get(x.charAt(i));
				if(s != null)
					score += s;
			}
			if(score > max){
				max = score;
				maxByte = b2;
				maxString = x;
			}
		}
		for(int i=0; i<b1.length; i++)
			b3[i] =  (byte) (b1[i]^maxByte);

		System.out.println("~~~~~~~~~~~~");
		System.out.println(maxString);
		System.out.println(DatatypeConverter.printHexBinary(b3));
		System.out.println(maxByte);	
		
	}
	
	public void C4() throws Exception{
		BufferedReader br = new BufferedReader(new FileReader("4.txt"));
		
		Map<Character, Double> freq = frequencyEnglish();
		byte maxByte = 0;
		double max = 0;
		String maxString = "";
		while(true){
			String line = br.readLine();
			if(line == null)
				break;
			byte[] b1 = DatatypeConverter.parseHexBinary(line); 
			byte[] b3 = new byte[b1.length];
			for(byte b2 = 0; b2 >= 0; b2++){
				double score = 0;
				for(int i=0; i<b1.length; i++)
					b3[i] =  (byte) (b1[i]^b2);
				String x = new String(b3);
				for(int i=0;i<x.length();i++){
					Double s = freq.get(x.charAt(i));
					if(s != null)
						score += s;
				}
				if(score > max){
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

	public static boolean isEncryptedProfileAdmin(byte[] data) throws Exception {
		Map<String, String> map = parseKeyValueSet(new String(decryptECB(data,
				randomKey)));
		return "admin".equals(map.get("role"));

	}

	public static void main(String[] args) throws Exception {
		instance.C17();
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
		print(attackCBCPaddingOracle(s));

	}

}