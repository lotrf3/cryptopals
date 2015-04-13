package cryptopals;

import java.util.Arrays;

public class CTR {

	public CTR(byte[] nonce, byte[] key) {
		this.nonce = nonce;
		this.key = key;
	}

	byte[] nonce;
	byte[] key;
	int blockSize = 16;
	int emptyPrefixLength = 8;

	public byte[] encrypt(byte[] data) throws Exception {
		return decrypt(data);
	}
	
	private void increment(byte[] counter){
		for(int i=0;i<counter.length - emptyPrefixLength;i++){
			if(counter[emptyPrefixLength + i]+1 != Byte.MAX_VALUE){
				counter[emptyPrefixLength + i]++;
				return;
			}
			counter[emptyPrefixLength + i] = 0;
		}
	}

	public byte[] decrypt(byte[] data) throws Exception {

		byte[] res = Arrays.copyOf(data, data.length);
		byte[] counter = Arrays.copyOf(nonce, nonce.length);
		for (int i = 0; i * blockSize < data.length; i++) {
			byte[] keystream = Encryption.encryptECB(counter, key);
			increment(counter);
			int l = data.length - (i + 1) * blockSize;
			l += blockSize;
			l = Math.min(blockSize, l);
			Encryption.repeatingXOR(keystream, 0, blockSize, res, i
						* blockSize, l , res, i * blockSize, l);
				
		}
		return res;
	}
}
