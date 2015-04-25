package cryptopals;

import java.math.BigInteger;
import java.util.Arrays;

public class MITMDiffieHellmanExchangeGP extends DiffieHellmanExchange {

	public void beginHandshake(BigInteger p, BigInteger g, BigInteger A) {
		this.p = p;
		assert p.equals(g);
		this.g = g;
		this.A = A;
	}

	public void acknowledgeHandshake(BigInteger B) {
		this.B = B;
	}

	public void sendMessage(byte[] msg) {
		this.msg = msg;
		SHA1 sha1 = new SHA1();
		byte[] ciphertxt = Arrays.copyOf(msg, msg.length - 16);
		byte[] iv = Arrays.copyOfRange(msg, msg.length - 16, msg.length);
		byte[] key = Arrays.copyOf(sha1.hash(new byte[] { 0 }), 16);
		try {
			Utils.print(Encryption.unpad(Encryption.decryptCBC(ciphertxt, key,
					iv)));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
