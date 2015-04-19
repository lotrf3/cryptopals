package cryptopals;

import java.util.Arrays;

public class SHA1 {

	public SHA1() {
	}

	public byte[] hash(int[] blks, int h0, int h1, int h2, int h3, int h4) {
		int[] w = new int[80];
		for (int i = 0; i < blks.length; i += 16) {
			int a = h0;
			int b = h1;
			int c = h2;
			int d = h3;
			int e = h4;

			int f, k;
			for (int j = 0; j < 80; j++) {
				if (j < 16)
					w[j] = blks[i + j];
				else
					w[j] = rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16],
							1);

				if (j < 20) {
					f = (b & c) | ((~b) & d);
					k = 0x5A827999;
				} else if (j < 40) {
					f = (b ^ c ^ d);
					k = 0x6ED9EBA1;
				} else if (j < 60) {
					f = ((b & c) | (b & d) | (c & d));
					k = 0x8F1BBCDC;
				} else {
					f = (b ^ c ^ d);
					k = 0xCA62C1D6;
				}
				int temp = rotate(a, 5) + f + e + k + w[j];
				e = d;
				d = c;
				c = rotate(b, 30);
				b = a;
				a = temp;

			}
			h0 = h0 + a;
			h1 = h1 + b;
			h2 = h2 + c;
			h3 = h3 + d;
			h4 = h4 + e;

		}

		byte[] res = {
				(byte) (h0 >>> 24),
				(byte) (h0 >>> 16),
				(byte) (h0 >>> 8),
				(byte) (h0 >>> 0),
				(byte) (h1 >>> 24),
				(byte) (h1 >>> 16),
				(byte) (h1 >>> 8),
				(byte) (h1 >>> 0),
				(byte) (h2 >>> 24),
				(byte) (h2 >>> 16),
				(byte) (h2 >>> 8),
				(byte) (h2 >>> 0),
				(byte) (h3 >>> 24),
				(byte) (h3 >>> 16),
				(byte) (h3 >>> 8),
				(byte) (h3 >>> 0),
				(byte) (h4 >>> 24),
				(byte) (h4 >>> 16),
				(byte) (h4 >>> 8),
				(byte) (h4 >>> 0) };

		
		return res;
	}

	public byte[] hash(byte[] msg) {
		long ml = msg.length * 8;

		int padding = 64 - ((msg.length + 8) % 64) + 8;
		byte[] padded = Arrays.copyOf(msg, msg.length + padding);
		padded[msg.length] = (byte) 0x80;
		for (int i = 0; i < 8; i++)
			padded[padded.length - 8 + i] = (byte) (ml >>> (8 - i - 1 << 3));// ???

		int h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
		int[] ints = Utils.bytesToInts(padded);
		byte[] res =  hash(ints, h0, h1, h2, h3, h4);

		return res;
	}

	private static int rotate(int num, int cnt) {
		return (num << cnt) | (num >>> (32 - cnt));
	}
}
