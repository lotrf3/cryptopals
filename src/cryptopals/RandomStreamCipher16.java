package cryptopals;

import java.util.Random;

public class RandomStreamCipher16 {
	
	public final int MAX_KEY_SIZE = 0xffff;
	Random random;
	public RandomStreamCipher16(Random r){
		random = r;
	}
	
	public byte[] encrypt(byte[] data){
		byte[] res = new byte[data.length];
		random.nextBytes(res);
		return Encryption.repeatingXOR(res,data);
	}
	public byte[] decrypt(byte[] data){
		return encrypt(data);
	}
	
	public void setSeed(int seed){
		random.setSeed(seed & MAX_KEY_SIZE);
	}

}
