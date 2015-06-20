package cryptopals;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

public class SRPSimpleMITM {

	public SRPServerSimpleMITM server;
	public SRPClientSimple client;
	private String dictPath;

	public SRPSimpleMITM(BigInteger N, BigInteger g, String dictPath) {
		server = new SRPServerSimpleMITM();
		server.N = N;
		server.g = g;
		this.dictPath = dictPath;
	}

	public class SRPServerSimpleMITM extends SRPServerSimple {

		BigInteger N, g;
		DiffieHellman dh;
		String username;
		byte[] salt = new byte[4];
		byte[] mac;

		@Override
		public boolean authenticate(SRPClientSimple client, String user,
				BigInteger clientPublicKey) {
			dh = new DiffieHellman(random);
			dh.g = g;
			dh.p = N;
			dh.A = clientPublicKey;
			username = user;
			return client.handshake(this, salt, g, BigInteger.ONE);
		}

		@Override
		public boolean verify(SRPClientSimple client, byte[] mac) {
			this.mac = mac;
			return true;
		}
	}

	public boolean attemptHash(String password) {
		BigInteger x = server.getHash(server.salt, password);
		BigInteger S = server.dh.A.multiply(server.g.modPow(x, server.N)).mod(
				server.N);
		byte[] k = SRP.sha1.hash(S.toByteArray());
		return Utils.equals(SRP.hmac.hmac(k, server.salt), server.mac);
	}

	public boolean crackHash() {

		try {
			BufferedReader br = new BufferedReader(new FileReader(dictPath));
			String line = br.readLine();
			while (line != null) {
				if (attemptHash(line)) {
					client = new SRPClientSimple(server.N, server.g,
							server.username, line);
					br.close();
					return true;
				}
				line = br.readLine();
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
}
