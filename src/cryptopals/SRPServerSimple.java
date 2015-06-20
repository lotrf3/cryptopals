package cryptopals;

import java.math.BigInteger;

public class SRPServerSimple extends SRP {

	BigInteger N, g, v, u;
	DiffieHellman dh;
	String username;
	byte[] salt;
	boolean isAuth;

	public void createUser(BigInteger N, BigInteger g, String username,
			String password) {
		this.N = N;
		this.g = g;
		this.username = username;
		salt = new byte[4];
		random.nextBytes(salt);
		v = g.modPow(getHash(salt, password), N);
	}

	public boolean authenticate(SRPClientSimple client, String user,
			BigInteger clientPublicKey) {
		assert (username.equals(user));
		dh = new DiffieHellman(random);
		dh.g = g;
		dh.p = N;
		dh.A = clientPublicKey;
		byte[] uBytes = new byte[16];
		random.nextBytes(uBytes);
		u = new BigInteger(uBytes);
		return client.handshake(this, salt, dh.getB(), u);
	}

	public boolean verify(SRPClientSimple client, byte[] mac) {
		BigInteger S = dh.A.multiply(v.modPow(u, N)).modPow(dh.b, N);
		byte[] K = sha1.hash(S.toByteArray());
		return isAuth = Utils.equals(hmac.hmac(K, salt), mac);
	}
}
