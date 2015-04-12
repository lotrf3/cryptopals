package cryptopals;

import javax.xml.bind.DatatypeConverter;

public class S1C1 {

	public static void main(String[] args){
		String hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
		String out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
		String b64 = DatatypeConverter.printBase64Binary(DatatypeConverter.parseHexBinary(hex));
		System.out.println(b64);
		System.out.println(out);	
	}
}
