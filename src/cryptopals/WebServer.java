package cryptopals;

interface WebServer {
	byte[] encrypt(byte[] data) throws Exception;

	byte[] decrypt(byte[] data) throws Exception;
}