package cryptopals;

import java.math.BigInteger;
import java.util.Arrays;

public class MITMDiffieHellmanExchangeP extends DiffieHellmanExchange {

	public void beginHandshake(BigInteger p, BigInteger g, BigInteger A) {
		this.p = p;
		this.g = g;
		this.A = p;
	}

	public void acknowledgeHandshake(BigInteger B) {
		this.B = p;
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
