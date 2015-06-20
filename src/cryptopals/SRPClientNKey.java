package cryptopals;

import java.math.BigInteger;

public class SRPClientNKey extends SRPClient {

	public SRPClientNKey(BigInteger N, BigInteger g, BigInteger k,
			String username) {
		super(N, g, k, username, "");
	}

	@Override
	public boolean authenticate(SRPServer server) {
		dh = new DiffieHellman(random);
		dh.g = g;
		dh.p = N;
		dh.A = dh.a = N;
		return server.authenticate(this, username, dh.A);
	}

	@Override
	public boolean handshake(SRPServer server, byte[] salt,
			BigInteger serverPublicKey) {
		this.salt = salt;
		dh.B = serverPublicKey;
		BigInteger S = BigInteger.ZERO;
		byte[] K = sha1.hash(S.toByteArray());
		return server.verify(this, hmac.hmac(K, salt));
	}
}
