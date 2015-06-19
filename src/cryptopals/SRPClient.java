package cryptopals;

import java.math.BigInteger;

public class SRPClient extends SRP {
	BigInteger N, g, k;
	byte[] salt;
	String username, password;
	DiffieHellman dh;

	public SRPClient(BigInteger N, BigInteger g, BigInteger k, String username,
			String password) {
		this.N = N;
		this.g = g;
		this.k = k;
		this.username = username;
		this.password = password;
	}

	public boolean authenticate(SRPServer server) {
		dh = new DiffieHellman(random);
		dh.g = g;
		dh.p = N;
		return server.authenticate(this, username, dh.getA());
	}

	public boolean handshake(SRPServer server, byte[] salt,
			BigInteger serverPublicKey) {
		this.salt = salt;
		dh.B = serverPublicKey;

		BigInteger u = getU(dh.A, dh.B);
		BigInteger x = getHash(salt, password);
		// (B - k*(g^x % N))^(a+u*x) % N
		BigInteger S = dh.B.subtract(k.multiply(g.modPow(x, N))).modPow(
				dh.a.add(u.multiply(x)), N);
		byte[] K = sha1.hash(S.toByteArray());
		return server.verify(this, hmac.hmac(K, salt));
	}

}
