import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.DecimalFormat;


public abstract class SHA {
	
	public abstract void reset();
	
	public abstract byte[] getHash();
	
	public abstract void update(byte b);
	
	public void update(byte[] b) { for (int i = 0; i < b.length; i++) update(b[i]); }
	
	public void update(String filename) {
		
		try {
			
			FileInputStream in = new FileInputStream(filename);
			
			System.out.println("READING FILE");
			
			int next = in.read();
			
			while (next != -1) {
				
				update((byte)(next & 0xFF));
				next = in.read();
				
			}
			
			in.close();
			
		} catch (FileNotFoundException e) {
			System.out.println("Could not find file!");
			System.exit(-1);
		} catch (IOException e) {
			System.out.println("Could not read from file!");
			System.exit(-1);
		} 
		
	}
	
	public String printBytes(byte[] b) {
		
		String s = "", str = "";
		
		for (int i = 0; i < b.length; i++) {
			
			s = "00" + Integer.toHexString(b[i] & 0xFF);
			str += s.substring(s.length()-2);
			
		}
		
		return str;
		
	}
	
	public String printHash() { return printBytes(getHash()); }
		
}
