
public class SHA2_OP extends SHA {
	
	public static void main(String[] args) { 
		
		SHA2_OP sha2 = new SHA2_OP();
		
		if (args.length == 1) sha2.update(args[0].getBytes());
		else if (args.length == 2 && args[0] == "-f") sha2.update(args[1]);
		
		System.out.println(sha2.printHash());
	}
	
	private static final int ch  (int a, int b, int c) { return (a & b) ^ (~a & c); }
	private static final int maj (int a, int b, int c) { return (a & b) ^ (a & c) ^ (b & c); }
	
	private static final int ep0 (int a) { return Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22); }
	private static final int ep1 (int a) { return Integer.rotateRight(a, 6) ^ Integer.rotateRight(a, 11) ^ Integer.rotateRight(a, 25); }
	
	private static final int sig0(int a) { return Integer.rotateRight(a, 7 ) ^ Integer.rotateRight(a, 18) ^ (a >>> 3); }
	private static final int sig1(int a) { return Integer.rotateRight(a, 17) ^ Integer.rotateRight(a, 19) ^ (a >>> 10); }
	
	private void processBuffer() {
		
		int a, b, c, d, e, f, g, h, i, j, temp1, temp2;
		int[] w = new int[64];
		
		a = hash[0];
		b = hash[1];
		c = hash[2];
		d = hash[3];
		e = hash[4];
		f = hash[5];
		g = hash[6];
		h = hash[7];
		
		for (i = 0; i < 16; i++) {
			
			j = 4*i;
			
			w[i] = 	  (int)(buffer[j  ] & 0xFF) << 24
					| (int)(buffer[j+1] & 0xFF) << 16
					| (int)(buffer[j+2] & 0xFF) << 8
					| (int)(buffer[j+3] & 0xFF);
			
		}
		
		for (; i < 64; i++) 
			w[i] = w[i-16] + sig0(w[i-15]) + w[i-7] + sig1(w[i-2]);
		
		for (i = 0; i < 64; i++) {
			
			temp1 = h + ep1(e) + ch(e,f,g) + k[i] + w[i];
			temp2 = ep0(a) + maj(a,b,c);
			
			h = g;
			g = f;
			f = e;
			e = (d + temp1)     & 0xFFFFFFFF;
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) & 0xFFFFFFFF;
			
		}
		
		hash[0] = (hash[0] + a) & 0xFFFFFFFF;
		hash[1] = (hash[1] + b) & 0xFFFFFFFF;
		hash[2] = (hash[2] + c) & 0xFFFFFFFF;
		hash[3] = (hash[3] + d) & 0xFFFFFFFF;
		hash[4] = (hash[4] + e) & 0xFFFFFFFF;
		hash[5] = (hash[5] + f) & 0xFFFFFFFF;
		hash[6] = (hash[6] + g) & 0xFFFFFFFF;
		hash[7] = (hash[7] + h) & 0xFFFFFFFF;
		
		bufferCount = 0;
		
	}
	
	private static final int[] k = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	
	private int[] hash = new int[8];
	private long  messageLength;
	
	private byte[] buffer = new byte[64];
	private int bufferCount;

	public SHA2_OP() { reset(); }

	public void update(byte b) {
		
		buffer[bufferCount++] = b;
		messageLength += 8;
		
		if (bufferCount == 64) processBuffer();
		
	}

	public byte[] getHash() {
		
		addPadding();
		
		processBuffer();
		
		byte[] digest = new byte[32];
		
		for (int i = 0; i < 8; i++) {
			
			int nextInt = hash[i];
			
			digest[i*4    ] = (byte) ((nextInt >>> 24) & 0xFF);
			digest[i*4 + 1] = (byte) ((nextInt >>> 16) & 0xFF);
			digest[i*4 + 2] = (byte) ((nextInt >>>  8) & 0xFF);
			digest[i*4 + 3] = (byte) ((nextInt       ) & 0xFF);
			
		}
		
		reset();
		
		return digest;
		
	}

	private void addPadding() {
		
		buffer[bufferCount++] = (byte) 0x80;
		
		if (bufferCount > 56) {
			
			while (bufferCount < 64) buffer[bufferCount++] = (byte) 0x00;
			
			processBuffer();
			
		}		
		
		while (bufferCount < 56) buffer[bufferCount++] = (byte) 0x00;
		
		buffer[56] = (byte)(messageLength >>> 56);
		buffer[57] = (byte)(messageLength >>> 48);
		buffer[58] = (byte)(messageLength >>> 40);
		buffer[59] = (byte)(messageLength >>> 32);
		buffer[60] = (byte)(messageLength >>> 24);
		buffer[61] = (byte)(messageLength >>> 16);
		buffer[62] = (byte)(messageLength >>> 8 );
		buffer[63] = (byte)(messageLength       );
		
	}
	
	public void reset() {
		
		hash[0] = 0x6a09e667;
		hash[1] = 0xbb67ae85;
		hash[2] = 0x3c6ef372;
		hash[3] = 0xa54ff53a;
		hash[4] = 0x510e527f;
		hash[5] = 0x9b05688c;
		hash[6] = 0x1f83d9ab;
		hash[7] = 0x5be0cd19;
		
		messageLength = 0;
		bufferCount = 0;
		
	}

}
