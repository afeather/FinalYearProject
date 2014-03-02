
public class SHA3 extends SHA {
	
	public static void main(String[] args) {
		
		SHA3 sha3 = new SHA3();
		
		if (args.length == 1) sha3.update(args[0].getBytes());
		else if (args.length == 2 && args[0] == "-f") sha3.update(args[1]);
		
		System.out.println(sha3.printHash());
		
	}
	
	private final long[] RC = new long[] {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
		0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
		0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
		0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
		0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
		0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
		0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
		0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
	};
	
	private final int[] R = new int[] {
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
		25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
	};
	
	private final int length = 32;
	private final int blockLength = 136;
	
	private long[] state;
	
	private byte[] buffer = new byte[blockLength];
	private int bufferCount;
	
	public SHA3() { reset(); }
	
	public void reset() {
		
		this.state = new long[25];
		
		bufferCount = 0;
		
	}
	
	public void update(byte b) {
		
		buffer[bufferCount++] = b;
		
		if (bufferCount == blockLength)
			processBuffer();
		
	}
	
	private void processBuffer() {
		
		for (int i = 0; i < blockLength; i += 8)
			this.state[i/8] ^= toLittle(buffer, i);
		
		keccakf();
		
		bufferCount = 0;
		
	}
	
	public byte[] getHash() {
		
		addPadding();
		
		processBuffer();
		
		byte[] digest = new byte[length];
		
		for (int i = 0; i < length; i+=8) {
			
			byte[] temp = fromLittle(state[i/8]);
			
			System.arraycopy(temp, 0, digest, i, 8);
			
		}
		
		reset();
		
		return digest;
		
	}
	
	private void addPadding() {
		
		if (bufferCount == blockLength - 1)
			buffer[135] = (byte) 0x81;
		
		else {
			
			buffer[bufferCount++] = (byte) 0x01;
			
			while (bufferCount < blockLength - 1)
				buffer[bufferCount++] = (byte) 0x00;
			
			buffer[135] = (byte) 0x80;
			
		}
		
	}
	
	private void keccakf() {
		
		long[] B, C, D;
		
		for (int round = 0; round < 24; round++) {
		
			B = new long[25];
			C = new long[5];
			D = new long[5];
			
			for (int i = 0; i < 5; i++) 
				C[i] = state[index(i,0)] ^ state[index(i,1)] 
					 ^ state[index(i,2)] ^ state[index(i,3)] 
					 ^ state[index(i,4)];
			
			for (int i = 0; i < 5; i++) {
				
				D[i] =   C[index(i-1)] 
					 ^ ((C[index(i+1)] << 1) | (C[index(i+1)] >>> (64 - 1)));
				
				for (int j = 0; j < 5; j++) 
					state[index(i, j)] ^= D[i];
				
			}
			
			for (int i = 0; i < 5; i++) 
				for (int j = 0; j < 5; j++) 
					B[index(j, i * 2 + 3 * j)] = ((state[index(i,j)] << R[index(i,j)]) 
					| (state[index(i,j)] >>> (64 - R[index(i,j)])));
				
			for (int i = 0; i < 5; i++) 
				for (int j = 0; j < 5; j++) 
					state[index(i,j)] = B[index(i,j)] ^ (~B[index(i+1, j)] 
									  & B[index(i+2, j)]);
			
			state[0] ^= RC[round];
			
		}
		
	}
	
	private long toLittle(byte[] bytes, int index) {
		
		return    (long) (bytes[index    ] & 0xFF)
				| (long) (bytes[index + 1] & 0xFF) << 8
				| (long) (bytes[index + 2] & 0xFF) << 16
				| (long) (bytes[index + 3] & 0xFF) << 24
				| (long) (bytes[index + 4] & 0xFF) << 32
				| (long) (bytes[index + 5] & 0xFF) << 40
				| (long) (bytes[index + 6] & 0xFF) << 48
				| (long) (bytes[index + 7] & 0xFF) << 56;
		
	}
	
	private byte[] fromLittle(long n) {
		
		byte[] out = new byte[8];
		
		out[0] = (byte)  n        ;
		out[1] = (byte) (n >>> 8 );
		out[2] = (byte) (n >>> 16);
		out[3] = (byte) (n >>> 24);
		out[4] = (byte) (n >>> 32);
		out[5] = (byte) (n >>> 40);
		out[6] = (byte) (n >>> 48);
		out[7] = (byte) (n >>> 56);
		
		return out;
	}
	
	private final int index(int a)        { return ( a + 5 ) % 5; }
	
	private final int index(int a, int b) { return index( a ) + ( 5 * index( b )); }
	
}
