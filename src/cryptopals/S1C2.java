package cryptopals;

import javax.xml.bind.DatatypeConverter;

public class S1C2 {
	
	public static void main(String[] args){
		String p1 = "1c0111001f010100061a024b53535009181c";
		String p2 = "686974207468652062756c6c277320657965";
		String out= "746865206b696420646f6e277420706c6179";
		byte[] b1 = DatatypeConverter.parseHexBinary(p1);
		byte[] b2 = DatatypeConverter.parseHexBinary(p2);
		byte[] b3 = new byte[b1.length];
		for(int i=0; i<b1.length; i++)
			b3[i] = (byte) (b1[i]^b2[i]);
		System.out.println(DatatypeConverter.printHexBinary(b3));
		System.out.println(out);	
	}
}
