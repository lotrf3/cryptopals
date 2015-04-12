package cryptopals;

interface TestAttack {
	boolean test(WebServer s, byte[] injection) throws Exception;
}