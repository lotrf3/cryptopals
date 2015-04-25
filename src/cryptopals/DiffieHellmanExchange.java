package cryptopals;

import static cryptopals.Utils.print;

import java.math.BigInteger;
import java.util.Arrays;

public class DiffieHellmanExchange {
	BigInteger p, g, A, B;
	byte[] msg;

	public void beginHandshake(BigInteger p, BigInteger g, BigInteger A) {
		this.p = p;
		this.g = g;
		this.A = A;
	}

	public void acknowledgeHandshake(BigInteger B) {
		this.B = B;
	}

	public void sendMessage(byte[] msg) {
		this.msg = msg;
	}

	public void run(DiffieHellman alice, DiffieHellman bob, byte[] iv)
			throws Exception {
		SHA1 sha1 = new SHA1();
		beginHandshake(alice.p, alice.g, alice.getA());
		bob.p = p;
		bob.g = g;
		bob.A = A;
		acknowledgeHandshake(bob.getB());
		alice.B = B;
		byte[] aliceMsg = "hello".getBytes();
		byte[] aKey = alice.getSessionKey();
		byte[] bKey = bob.getSessionKey();
		byte[] aliceSessionKey = Arrays.copyOf(sha1.hash(aKey), 16);
		byte[] bobSessionKey = Arrays.copyOf(sha1.hash(bKey), 16);
		assert Utils.equals(aliceSessionKey, bobSessionKey);
		byte[] message = Utils.concat(
				Encryption.encryptCBC(aliceMsg, aliceSessionKey, iv), iv);
		sendMessage(message);

		byte[] ciphertxt = Arrays.copyOf(msg, msg.length - 16);
		byte[] ivBob = Arrays.copyOfRange(msg, msg.length - 16, msg.length);
		byte[] plaintxt = Encryption.unpad(Encryption.decryptCBC(ciphertxt,
				bobSessionKey, ivBob));
		print(plaintxt);
		assert Utils.equals(aliceMsg, plaintxt);

	}
}
