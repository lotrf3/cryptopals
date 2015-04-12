package cryptopals;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

public class S1C4 {

	
	
	public static void main(String[] args) throws IOException{
		BufferedReader br = new BufferedReader(new FileReader("4.txt"));
		
		Map<Character, Double> freq = frequencyEnglish();
		byte maxByte = 0;
		double max = 0;
		String maxString = "";
		while(true){
			String line = br.readLine();
			if(line == null)
				break;
			byte[] b1 = DatatypeConverter.parseHexBinary(line); 
			byte[] b3 = new byte[b1.length];
			for(byte b2 = 0; b2 >= 0; b2++){
				double score = 0;
				for(int i=0; i<b1.length; i++)
					b3[i] =  (byte) (b1[i]^b2);
				String x = new String(b3);
				for(int i=0;i<x.length();i++){
					Double s = freq.get(x.charAt(i));
					if(s != null)
						score += s;
				}
				if(score > max){
					max = score;
					maxByte = b2;
					maxString = x;
				}
			}
		}

		System.out.println("~~~~~~~~~~~~");
		System.out.println(maxString);
		System.out.println(maxByte);
		br.close();
	}
	
	public static Map<Character, Double> frequencyEnglish(){
		HashMap<Character, Double> a = new HashMap<Character, Double>();
		a.put('a', 8.167);
		a.put('b', 1.492);
		a.put('c', 2.782);
		a.put('d', 4.253);
		a.put('e', 12.702);
		a.put('f', 2.228);
		a.put('g', 2.015);
		a.put('h', 6.094);
		a.put('i', 6.966);
		a.put('j', 0.153);
		a.put('k', 0.772);
		a.put('l', 4.025);
		a.put('m', 2.406);
		a.put('n', 6.749);
		a.put('o', 7.507);
		a.put('p', 1.929);
		a.put('q', 0.095);
		a.put('r', 5.987);
		a.put('s', 6.327);
		a.put('t', 9.056);
		a.put('u', 2.758);
		a.put('v', 0.978);
		a.put('w', 2.360);
		a.put('x', 0.150);
		a.put('y', 1.974);
		a.put('z', 0.074);
		a.put('A', 8.167);
		a.put('B', 1.492);
		a.put('C', 2.782);
		a.put('D', 4.253);
		a.put('E', 12.702);
		a.put('F', 2.228);
		a.put('G', 2.015);
		a.put('H', 6.094);
		a.put('I', 6.966);
		a.put('J', 0.153);
		a.put('K', 0.772);
		a.put('L', 4.025);
		a.put('M', 2.406);
		a.put('N', 6.749);
		a.put('O', 7.507);
		a.put('P', 1.929);
		a.put('Q', 0.095);
		a.put('R', 5.987);
		a.put('S', 6.327);
		a.put('T', 9.056);
		a.put('U', 2.758);
		a.put('V', 0.978);
		a.put('W', 2.360);
		a.put('X', 0.150);
		a.put('Y', 1.974);
		a.put('Z', 0.074);
		a.put(' ', 15.0);
		
		return a;
	}
}
