package cryptopals;

public class ArrayUtils {
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
		for (int i = 0; i < a.length; i++) {
			if (equals(a, i, b, 0, b.length))
				return i;
		}
		return -1;
	}

}
