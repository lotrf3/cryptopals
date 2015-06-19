package cryptopals;

import java.math.BigInteger;

public class SRPServer extends SRP {

	BigInteger N, g, k, v;
	DiffieHellman dh;
	String username;
	byte[] salt;
	boolean isAuth;

	public void createUser(BigInteger N, BigInteger g, BigInteger k,
			String username, String password) {
		this.N = N;
		this.g = g;
		this.k = k;
		this.username = username;
		salt = new byte[4];
		random.nextBytes(salt);
		v = g.modPow(getHash(salt, password), N);
	}

	public boolean authenticate(SRPClient client, String user,
			BigInteger clientPublicKey) {
		assert (username.equals(user));
		dh = new DiffieHellman(random);
		dh.g = g;
		dh.p = N;
		dh.A = clientPublicKey;
		dh.B = k.multiply(v).add(dh.getB());
		return client.handshake(this, salt, dh.B);
	}

	public boolean verify(SRPClient client, byte[] mac) {
		BigInteger u = getU(dh.A, dh.B);
		BigInteger S = dh.A.multiply(v.modPow(u, N)).modPow(dh.b, N);
		byte[] K = sha1.hash(S.toByteArray());
		return isAuth = Utils.equals(hmac.hmac(K, salt), mac);
	}

}
