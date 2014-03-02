import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.DecimalFormat;

/*
Alex Feather
B119899

This is the SHA class. It provides the update, getHash and reset methods for the other
hashing programs. This was mostly to allow the testing classes to call any of the
programs. Also it provides consistency throughout the classes.
*/

public abstract class SHA {
	
	//the reset method is used to set the variables back to their default values
	public abstract void reset();
	
	//getHash is used to extract the hash
	public abstract byte[] getHash();
	
	//this method updates the buffer one byte at a time. This was chosen because it
	//easily allows the message to be updated from a file or a string
	public abstract void update(byte b);
	
	//this helper method calls the update(byte) method on every byte in a byte array
	public void update(byte[] b) { for (int i = 0; i < b.length; i++) update(b[i]); }
	
	//this helper method calls the update(byte) method on every byte in a file given
	//the file name
	public void update(String filename) {
		
		try {
			
			//First we try to open the file
			FileInputStream in = new FileInputStream(filename);
			
			//tell the user the file was opened
			System.out.println("READING FILE");
			
			int next;
			
			//read in bytes from the file as integers
			while ((next = in.read()) != -1) update((byte)(next & 0xFF));
			
			//close the input stream
			in.close();
			
		//if cannot find the file print message to console and exit
		} catch (FileNotFoundException e) {
			System.out.println("Could not find file!");
			System.exit(-1);
		
		//if cannot read from the file print message to console and exit
		} catch (IOException e) {
			System.out.println("Could not read from file!");
			System.exit(-1);
		} 
		
	}
	
	//helper method to print the bytes in an array
	public String printBytes(byte[] b) {
		
		//string to store the final output and the working string
		String s = "", str = "";
		
		//for each byte in the array
		for (int i = 0; i < b.length; i++) {
			
			//we concatenate the hexstring of the byte to "00"
			//and then get the last two characters
			//this is to ensure that the length of printing one
			//byte will always be 2 characters
			s = "00" + Integer.toHexString(b[i] & 0xFF);
			str += s.substring(s.length()-2);
			
		}
		
		return str;
		
	}
	
	//this is a helper method to extract the state and print it
	public String printHash() { return printBytes(getHash()); }
		
}
