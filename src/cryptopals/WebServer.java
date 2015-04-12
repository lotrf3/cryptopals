package cryptopals;

interface WebServer {
	byte[] decrypt(byte[] data) throws Exception;

	byte[] encrypt(byte[] data) throws Exception;

}