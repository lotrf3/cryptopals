package cryptopals;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {

	SecureRandom random;
	BigInteger p, g, a, A, b, B, s;

	public DiffieHellman(SecureRandom random) {
		this.random = random;
		p = new BigInteger(
				"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
						+ "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
						+ "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
						+ "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
						+ "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
						+ "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
						+ "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
						+ "fffffffffffff", 16);
		g = BigInteger.valueOf(2);
	}

	public BigInteger getA() {
		if (a == null) {
			a = new BigInteger(8, random);
			A = g.modPow(a, p);
		}
		return A;
	}

	public BigInteger getB() {
		if (b == null) {
			b = new BigInteger(8, random);
			B = g.modPow(b, p);
		}
		return B;
	}

	public byte[] getSessionKey() {
		if (a != null)
			return B.modPow(a, p).toByteArray();
		else
			return A.modPow(b, p).toByteArray();
	}

}
