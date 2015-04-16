package cryptopals;

import java.util.Random;

public class MT19937 extends Random {
	private static final long serialVersionUID = 7590131823439013877L;

	public MT19937(int seed) {
		super(seed);
	}

	public MT19937(int[] state) {
		if (state.length != 624)
			throw new IllegalArgumentException();
		mt = state;
	}

	@Override
	public void setSeed(long seed) {
		if(mt == null)
			mt = new int[624];
		index = 0;
		mt[0] = (int) seed;
		for (int i = 1; i < 624; i++)
			mt[i] = 1812433253 * (mt[i - 1] ^ (mt[i - 1] >>> 30)) + i;

	}

	int[] mt;
	int index;

	private void generateNumbers() {
		for (int i = 0; i < 624; i++) {
			int y = (mt[i] & 0x80000000) + (mt[(i + 1) % 624] & 0x7fffffff);
			mt[i] = mt[(i + 397) % 624] ^ (y >>> 1);
			if ((y % 2) != 0)
				mt[i] = mt[i] ^ 0x9908b0df;
		}
	}

	@Override
	public int nextInt() {
		if (index == 0)
			generateNumbers();
		int e = mt[index];
		int d = e ^ (e >>> 11);
		int c = d ^ ((d << 7) & 0x9d2c5680);
		int b = c ^ ((c << 15) & 0xefc60000);
		int a = b ^ (b >>> 18);
		index = (index + 1) % 624;
		return a;
	}

	@Override
	protected int next(int bits) {
		int y = nextInt();
		return y >>> bits;
	}
}
