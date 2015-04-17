package cryptopals;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public class Utils {

	public void swapByteOrder(byte[] a) {
		for (int i = 0; i < a.length / 2; i++) {
			byte tmp = a[i];
			a[i] = a[a.length - 1 - i];
			a[a.length - 1 - i] = tmp;
		}
	}

	public static byte[] concat(byte[] a, byte[] b) {
		return concat(a, 0, a.length, b, 0, b.length);
	}

	public static byte[] concat(byte[] a, int aOffset, int aLength, byte[] b,
			int bOffset, int bLength) {
		byte[] res = new byte[aLength + bLength];
		System.arraycopy(a, aOffset, res, 0, aLength);
		System.arraycopy(b, bOffset, res, aLength, bLength);
		return res;
	}

	public static int containsBlock(byte[] data, byte[] block, int blockSize) {
		for (int i = 0; i < data.length; i += blockSize) {
			if (equals(data, i, block, 0, blockSize))
				return i;
		}
		return -1;
	}

	public static boolean equals(byte[] a, int aOffset, byte[] b, int bOffset,
			int length) {
		for (int i = 0; i < length; i++)
			if (a[aOffset + i] != b[bOffset + i])
				return false;
		return true;
	}

	public static boolean equals(byte[] a, byte[] b) {
		return a.length == b.length && equals(a, 0, b, 0, a.length);
	}

	public static int firstNonEqualByte(byte[] a, byte[] b) {
		return firstNonEqualByte(a, 0, b, 0, Math.min(a.length, b.length));
	}

	public static int firstNonEqualByte(byte[] a, int aOffset, byte[] b,
			int bOffset, int length) {
		for (int i = 0; i < length; i++) {
			if (a[aOffset + i] != b[bOffset + i])
				return i;
		}
		return -1;
	}

	public static int indexOf(byte[] a, byte[] b) {
		for (int i = 0; i + b.length <= a.length; i++) {
			if (equals(a, i, b, 0, b.length))
				return i;
		}
		return -1;
	}

	public static void print(byte data) {
		System.out.print((char) data);

	}

	public static void print(byte[] data) {
		System.out.println(new String(data));
	}

	static void print(String str) {
		System.out.println(str);
	}

	public static boolean isValidASCII(byte b) {
		return (b >= 20 && b <= 126) || b == '\n';
	}

	public static int[] bytesToInts(byte[] bytes) {

		IntBuffer intBuf = ByteBuffer.wrap(bytes).asIntBuffer();
		int[] ints = new int[intBuf.remaining()];
		intBuf.get(ints);
		return ints;
	}

}
