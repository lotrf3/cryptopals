package cryptopals;

import java.math.BigInteger;

public class SRPClientSimple extends SRP {
	BigInteger N, g;
	byte[] salt;
	String username, password;
	DiffieHellman dh;

	public SRPClientSimple(BigInteger N, BigInteger g, String username,
			String password) {
		this.N = N;
		this.g = g;
		this.username = username;
		this.password = password;
	}

	public boolean authenticate(SRPServerSimple server) {
		dh = new DiffieHellman(random);
		dh.g = g;
		dh.p = N;
		return server.authenticate(this, username, dh.getA());
	}

	public boolean handshake(SRPServerSimple server, byte[] salt,
			BigInteger serverPublicKey, BigInteger u) {
		this.salt = salt;
		dh.B = serverPublicKey;

		BigInteger x = getHash(salt, password);
		BigInteger S = dh.B.modPow(dh.a.add(u.multiply(x)), N);
		byte[] K = sha1.hash(S.toByteArray());
		return server.verify(this, hmac.hmac(K, salt));
	}

}
