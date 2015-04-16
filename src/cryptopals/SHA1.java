package cryptopals;

import java.security.MessageDigest;

public class SHA1 {
	MessageDigest sha1;
	
	public SHA1(){
		try{
			 sha1 = MessageDigest.getInstance("SHA-1");
		}
		catch(Exception ex){
			
		}
	}
	
	public byte[] hash(byte[] msg){
		return sha1.digest(msg);
	}

}
