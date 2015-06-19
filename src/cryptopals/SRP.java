package cryptopals;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SRP {
	static SecureRandom random = new SecureRandom();
	static SHA1 sha1 = new SHA1();
	static HMAC hmac = new HMAC(sha1);

	
	public BigInteger getHash(byte[] salt, String password){

		byte[] hash = sha1.hash(Utils.concat(salt, password.getBytes()));
		return new BigInteger(hash);
	}
	
	public BigInteger getU(BigInteger A, BigInteger B){
		byte[] uH = sha1.hash(Utils.concat(A.toByteArray(), B.toByteArray()));
		return new BigInteger(uH);
	}
}
