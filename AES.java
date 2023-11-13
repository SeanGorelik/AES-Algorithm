import java.util.*;
import java.io.*;

public class AES
{
    private static long sbox[][] = {{99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118},
            {202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192},
            {183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21},
            {4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117},
            {9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132},
            {83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207},
            {208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168},
            {81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210},
            {205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115},
            {96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219},
            {224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121},
            {231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8},
            {186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138},
            {112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158},
            {225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223},
            {140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22}};

    private static long invsbox[][]  = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

    private static String k = "";

    /*
     * This is the main method, it processes the inputs given and calls the necessary methods.
     */
    public static void main(String args[]){
        File msgFile = new File(args[0]);
        File keyFile = new File(args[1]);

        String pt = "";

        try{
            Scanner msgScanner = new Scanner(msgFile);
            Scanner keyScanner = new Scanner(keyFile);

            while(msgScanner.hasNextLine()){
                pt += msgScanner.nextLine();
            }

            while(keyScanner.hasNextLine()){
                k += keyScanner.nextLine();
            }

            msgScanner.close();
            keyScanner.close();
        }catch(FileNotFoundException e){
            System.out.println("File not found");
            e.printStackTrace();
        }

        String ptTemp[] = pt.split(" ");
        String kTemp[] = k.split(" ");
        String tempKExpansion = "";

        pt = fixInput(ptTemp);
        k = fixInput(kTemp);

        System.out.println("Plaintext");
        System.out.println(pt);

        System.out.println("Key");
        System.out.println(k);

        long expandedKey[][] = keyExpansion(k);
        System.out.println("Key Schedule:");
        for(int i = 0; i < expandedKey.length; i++){
            tempKExpansion="";
            for(int j = 0; j < expandedKey[i].length; j++){
                tempKExpansion += String.format("%08x", expandedKey[i][j]) + ","; //pad the expandedKey[i][j] with 0 so its 4 bytes
            }
            System.out.print(tempKExpansion.substring(0,tempKExpansion.length()-1)); //remove the comma at the end of each line
            System.out.println();
        }

        System.out.println("\nENCRYPTION PROCESS");
        System.out.println("------------------");
        System.out.println("Plain Text");
        printPlaintext(pt);
        System.out.println();

        long enc[][] = encrypt(pt);

        System.out.println("CipherText:");
        printArr(enc);
        System.out.println("\n");

        System.out.println("DECRYPTION PROCESS");
        System.out.println("------------------");
        System.out.println("CipherText:");
        printArr(enc);
        System.out.println();
        
        long dec[][] = decrypt(stateArrToHexString(enc));

        System.out.println("Plaintext:");
        printArr(dec);
        System.out.println("\nEnd of Processing");
    }

    /*
     * This is a helper method that takes in the plaintext (String)
     * and prints it in a clear way (with spaces between each byte)
     */
    private static void printPlaintext(String plaintext){
        String temp = "";
        for(int i = 0; i < plaintext.length(); i++){
            if(i % 8 == 0 && i != 0){ //print a tab after each 4 bytes
                System.out.print("\t");
            }
            temp += plaintext.charAt(i);
            if(temp.length() == 2){ //seperate each byte with a space
                System.out.print(temp + " ");
                temp = "";
            }
        }
        System.out.println();
    }

    /*
     * This method takes in a 2D array and prints it as a hex string (bytes seperated by spaces)
     */
    private static void printArr(long arr[][]){
        for(int i = 0; i < arr[0].length; i++){
            for(int j = 0; j < arr.length; j++){
                System.out.print(String.format("%02x ", arr[j][i]));
            }
            System.out.print("\t");
        }
        System.out.println();
    }

    /*
     * This method takes in a plaintext string and encrypts it
     * The output is the resultant 2D state array after encryption
     */
    public static long[][] encrypt(String plaintext){
        plaintext = plaintext.replace(" ", ""); //remove whitespace from plaintext (if there is any)
        k = k.replace(" ", ""); //remove whitespace from key (if there is any)
        long expandedKey[][] = keyExpansion(k);
        long s[][] = arrToStateArr(xorWithKey(split32Bit(plaintext), expandedKey[0])); // initial state (after xor with first key)

        for(int r = 1; r < 11; r++){
            s = subBytes(s);
            s = shiftRows(s);
            if(r<= 9){
                mixColumns(s);
                System.out.println("State after call " + r + " to mixColumns()");
                System.out.println("-------------------------------------");
                printArr(s);
                System.out.println();
            }
            s = xorStateArrWithKey(s, expandedKey[r]);
        }

        return s;
    }
    
    /*
     * This method takes in a ciphertext string and decrypts it
     * The output is the resultant 2D array after decryption
     */
    public static long[][] decrypt(String ciphertext){
        ciphertext = ciphertext.replace(" ", ""); //remove any whitespaces from ciphertext (if there is any)
        k = k.replace(" ", ""); //remove any whitespaces from key (if there is any)
        long expandedKey[][] = keyExpansion(k);
        long s[][] = arrToStateArr(split32Bit(ciphertext)); //convert the ciphertext into state array
        for(int r = 10; r >= 1; r--){
            s = xorStateArrWithKey(s, expandedKey[r]);
            if(r <= 9){
                invMixColumns(s);
                System.out.println("State after call " + (10-r) + " to invMixColumns()");
                System.out.println("-------------------------------------");
                printArr(s);
                System.out.println();
            }
            s = invShiftRows(s);
            s = invSubBytes(s);
        }
        s = arrToStateArr(xorWithKey(split32Bit(stateArrToHexString(s)), expandedKey[0])); // xor state s with first key (expandedKey[0])
        
        return s;
    }

    /*
     * This method takes in a state array and performs s-box substitutions
     * The output is a 2D array that is the result after all the s-box substitutions 
     */
    private static long[][] subBytes(long stateArr[][]){
        long toReturn[][] = new long[stateArr.length][stateArr[0].length];
        long row = -1;
        long col = -1;

        for(int i = 0; i < stateArr.length; i++){
            for(int j = 0; j < stateArr[i].length; j++){
                col = stateArr[i][j] % 16;
                row = stateArr[i][j] / 16;
                toReturn[i][j] = sbox[(int)row][(int)col];
            }
        }

        return toReturn;
    }

    /*
     * This method takes in a 2D state array and reverts the sbox substitutions
       that were performed on that array.
     * The output is a 2D state array that is the result of all the inverse s-box substitutions
     */
    private static long[][] invSubBytes(long stateArr[][]){
        long toReturn[][] = new long[stateArr.length][stateArr[0].length];
        long row = -1;
        long col = -1;

        for(int i = 0; i < stateArr.length; i++){
            for(int j = 0; j < stateArr[i].length; j++){
                col = stateArr[i][j] % 16;
                row = stateArr[i][j] / 16;
                toReturn[i][j] = invsbox[(int)row][(int)col];
            }
        }

        return toReturn;
    }

    /*
     * This method takes in a state array and shifts it's rows according to the algorithm (shifts to the left)
     * The output is a 2D state array that is the result after all rows have been shifted (although 1st row doesn't get shifted)
     */
    private static long[][] shiftRows(long stateArr[][]){
        long toReturn[][] = new long[stateArr.length][stateArr[0].length];
        long arrCopy[][] = copyArr(stateArr); //make a deep copy of the state array
        int shiftToCol = -1;

        for(int i = 0; i < stateArr.length; i++){
            for(int j = 0; j < stateArr[i].length; j++){
                shiftToCol = j - i;
                while (shiftToCol < 0)
                    shiftToCol += stateArr[i].length;
                toReturn[i][shiftToCol % (stateArr.length)] = arrCopy[i][j];
            }
        }

        return toReturn;
    }

    /*
     * This method takes in a state array and inversly shift it's rows according to the algorithm (shifts to the right)
     * The output is a 2D state array that is the result after all rows have been inversely shifted (although 1st row doesn't get shifted)
     */
    private static long[][] invShiftRows(long stateArr[][]){
        long toReturn[][] = new long[stateArr.length][stateArr[0].length];
        long arrCopy[][] = copyArr(stateArr); //make a deep copy of the state array
        int shiftToCol = -1;

        for(int i = 0; i < stateArr.length; i++){
            for(int j = 0; j < stateArr[i].length; j++){
                shiftToCol = j + i;
                while (shiftToCol < 0)
                    shiftToCol += stateArr[i].length;
                toReturn[i][shiftToCol % (stateArr.length)] = arrCopy[i][j];
            }
        }

        return toReturn;
    }

    /*
     * This method takes in a state array and does matrix multiplication in GF(256) on it
     */
    private static void mixColumns(long stateArr[][]){
        final long constMat[][] = {{0x02,0x03,0x01,0x01},{0x01,0x02,0x03,0x01},{0x01,0x01,0x02,0x03},{0x03,0x01,0x01,0x02}};
        long tempMat[][] = new long[stateArr.length][1];
        long newMat[][] = null;

        for(int i = 0; i < stateArr[0].length; i++){
            for(int j = 0; j < stateArr.length; j++){
                tempMat[j][0] = stateArr[j][i]; //store 1 column of the state array at a time
            }
            newMat = matrixMult(constMat, tempMat); //multiply matrices
            for(int k = 0; k < stateArr.length; k++){
                stateArr[k][i] = newMat[k][0]; //make the changes to the state array after the multiplication
            }
        }
    }

    /*
     * This method takes in a state array and does the inverse matrix multiplication in GF(256) on it
     */
    private static void invMixColumns(long stateArr[][]){
        final long constMat[][] = {{0x0e,0x0b,0x0d,0x09},{0x09,0x0e,0x0b,0x0d},{0x0d,0x09,0x0e,0x0b},{0x0b,0x0d,0x09,0x0e}};
        long tempMat[][] = new long[stateArr.length][1];
        long newMat[][] = null;

        for(int i = 0; i < stateArr[0].length; i++){
            for(int j = 0; j < stateArr.length; j++){
                tempMat[j][0] = stateArr[j][i]; //store 1 column of the state array at a time
            }
            newMat = invMatrixMult(constMat, tempMat); //multiply matrices
            for(int k = 0; k < stateArr.length; k++){
                stateArr[k][i] = newMat[k][0]; //make the changes to the state array after the multiplication
            }
        }
    }

    /*
     * This is a helper method for invMixColumns() which multiplies the inverse matrix by the state array
     * The output is a 2D array which is the result of multiplying the two matrices specified
     */
    private static long[][] invMatrixMult(long mat1[][], long mat2[][]){
        long finalMat[][] = new long[mat1.length][mat2[0].length];
        int col = 0;

        for(int i = 0; i < mat1.length; i++){
            for(int j = 0; j < mat1[i].length; j++){
                finalMat[i][col] ^= invMult(mat1[i][j], mat2[j][col]);
            }
            if(col < mat2[0].length-1){ //keep track of which column we are currently on
                col++;
                i-=1;
            }
            else{
                col = 0; //reset to first column after we reached last column of mat2
            }
        }

        return finalMat;
    }

    /*
     * This method takes in two values and stores the results of value b multiplied (GF(256)) by 1,2,4,8,16 in an array
     * The output is the array that stores the results of the operations stated above.
     */
    private static long[] multBuilder(long a, long b){
        long[] toReturn = new long[5];
        toReturn[0] = b;
        for(int i = 1; i < 5; i++){
            toReturn[i] = multByTwo(toReturn[i-1]);
        }
        return toReturn;
    }

    /*
     * This method takes in two values and outputs the result of their multiplication in GF(256)
     * Note that "a" can only take on 4 values: 0x09, 0x0e, 0x0b, 0x0d 
     */
    private static long invMult(long a, long b){
        long toReturn = -1;
        long multBuilderArr[] = multBuilder(a,b);

        if(a == 0x09){
            toReturn = multBuilderArr[0] ^ multBuilderArr[3];
        }
        else if(a == 0x0e){
            toReturn = multBuilderArr[1] ^ multBuilderArr[2] ^ multBuilderArr[3];
        }
        else if(a == 0x0b){
            toReturn = multBuilderArr[0] ^ multBuilderArr[1] ^ multBuilderArr[3];
        }
        else if(a == 0x0d){
            toReturn = multBuilderArr[0] ^ multBuilderArr[2] ^ multBuilderArr[3];
        }

        return toReturn;
    }

    /*
     * This method takes in an intial key and expands it into 11 keys
     * The output is a 2D array of the 11 keys where each row i is key[i] split into 4 bytes (so 11 rows and 4 columns)
     */
    private static long[][] keyExpansion(String k){
        long keyArr[][] = new long[11][4];
        long keySplit[] = split32Bit(k); //split initial key into 4 values where each value is 4 bytes long
        long c[] = {0x01000000L, 0x02000000L, 0x04000000L, 0x08000000L, 0x10000000L, 0x20000000L, 0x40000000L, 0x80000000L, 0x1B000000L, 0x36000000L};
        System.arraycopy(keySplit, 0, keyArr[0], 0, keySplit.length); //first row of keyArr is set to be the initial key

        for(int i = 1; i < 11; i++){
            keyArr[i][0] = keyArr[i-1][0] ^ stateArrToHex(subBytes(hexToStateArr(cyclicShift(keyArr[i-1][3])))) ^ c[i-1];
            keyArr[i][1] = keyArr[i-1][1] ^ keyArr[i][0];
            keyArr[i][2] = keyArr[i-1][2] ^ keyArr[i][1];
            keyArr[i][3] = keyArr[i-1][3] ^ keyArr[i][2];
        }

        return keyArr;
    }

    /*
     * This method takes in two matrices and returns the result of both of them multiplied (in GF(256))
     */
    private static long[][] matrixMult(long mat1[][], long mat2[][]){
        long finalMat[][] = new long[mat1.length][mat2[0].length];
        int col = 0;

        for(int i = 0; i < mat1.length; i++){
            for(int j = 0; j < mat1[i].length; j++){
                finalMat[i][col] ^= mult(mat1[i][j], mat2[j][col]);
            }
            if(col < mat2[0].length-1){ //keep track of which column we are currently on
                col++;
                i-=1;
            }
            else{
                col = 0; //reset to first column after we reached last column of mat2
            }
        }

        return finalMat;
    }

    /*
     * This method takes in two values and returns the result of both of them multiplied in GF(256)
     * Note that "a" can only take on 3 values: 0x01, 0x02, 0x03. This is because the only methods 
       that use this are matrixMult() and mixColumns(), so "a" taking on only these values is sufficient
       in this case.
     */
    private static long mult(long a, long b){
        long toReturn = -1;

        if(a == 0x01){
            toReturn = b;
        }
        else if(a == 0x02){
            toReturn = multByTwo(b);
        }
        else if(a == 0x03){
            toReturn = multByTwo(b) ^ b;
        }

        return toReturn;
    }

    /*
     * This method takes in a value and multiplies it by 2 in GF(256)
     * It's useful because if we can calculate multiplication by 2, 
       calculating multiplication by other numbers is a lot easier.
     */
    private static long multByTwo(long a){
        String temp = "";
        if ((a & 0x80) == 0x80){
            a ^= 0x80;
            temp = String.format("%8s", Long.toBinaryString(a)).replace(" ", "0"); //pad the binary string with 0s so it always has 8 bits 
            temp = temp.substring(1,temp.length()) + "0";
            a = Long.parseLong(temp,2);
            a ^= 0x1b;
        }
        else{
            temp = String.format("%8s", Long.toBinaryString(a)).replace(" ", "0"); //pad the binary string with 0s so it always has 8 bits
            temp = temp.substring(1,temp.length()) + "0";
            a = Long.parseLong(temp,2);
        }
        return a;
    }

    /*
     * This method takes in a hex string and splits it into 4 hex strings (each hex string is 4 bytes aka 32 bits)
     * The method outputs an array of those 4 hex strings
     */
    private static long[] split32Bit(String k){
        long toReturn[] = new long[k.length() / 8];
        String temp = "";
        int counter = 0;

        for(int i = 0; i < k.length(); i++){
            temp += k.charAt(i);
            if(temp.length() == 8){ //the condition is true every 4 bytes
                toReturn[counter++] = Long.parseLong(temp,16);
                temp = "";
            }
        }

        return toReturn;
    }

    /*
     * This method "fixes" the input by padding every byte given and returns the fixed input
     * e.g. if the input we are given is {1} then the method would output 01 since it pads it
       to 2 hex values with a 0.
     */
    private static String fixInput(String[] inp){
        String toReturn = "";
        for(int i = 0; i < inp.length; i++){
            toReturn += String.format("%2s",inp[i]).replace(" ", "0"); //pad to 2 hex values with 0s
        }
        return toReturn;
    }

    /*
     * This method converts a hex value into a state array and outputs that state array
     */
    private static long[][] hexToStateArr(long num){
        long arr[][] = new long[4][1];

        long firstHex = -1;
        long secondHex = -1;
        long finalHex = -1;

        for(int i = 0; i < 4; i++){
            firstHex = (num / 16) % 16; //get second hex value from the right of num
            secondHex = num % 16; //get first hex value from the right of num
            finalHex = (firstHex << 4) | secondHex; //join the two hex values above e.g. firstHex=0x5, secondHex=0x3 so finalHex=0x53
            num = num / 256; //remove the two hex values above from the right-end side of num
            arr[arr.length - i - 1][0] = finalHex; //put it into the state array row and column it belongs to
        }

        return arr;
    }

    /*
     * This method converts a 1D array into a 2D state array
     */
    private static long[][] arrToStateArr(long[] arr){
        long toReturn[][] = new long[4][4];

        long firstHex = -1;
        long secondHex = -1;
        long finalHex = -1;

        for(int i = 0; i < 4; i++){
            for(int j = 3; j >= 0; j--){
                firstHex = (arr[i] / 16) % 16; //get second hex value from the right of arr[i]
                secondHex = arr[i] % 16; //get first hex value from the right of arr[i]
                finalHex = (firstHex << 4) | secondHex; //join the two hex values above e.g. firstHex=0x5, secondHex=0x3 so finalHex=0x53
                arr[i] = arr[i] / 256; //remove the two hex values above from the right-end side of arr[i]
                toReturn[j][i] = finalHex; //put it into the state array row and column it belongs to
            }
        }

        return toReturn;
    }

    /*
     * This method takes in a state array and converts it into a hex value
     */
    private static long stateArrToHex(long s[][]){
        long finalHex = 0x00;

        for(int i = 0; i < 4; i++){
            finalHex = finalHex | (s[i][0] << (24-8*i));
        }

        return finalHex;
    }
    
    /*
     * This method takes in a state array and converts it into a hex string
     */
    private static String stateArrToHexString(long s[][]){
        String toReturn = "";
        
        for(int i = 0; i < s[0].length; i++){
            for(int j = 0; j < s.length; j++){
                toReturn += String.format("%02x", s[j][i]); //pad each byte with 0s so each byte is of length 2
            }
        }
        
        return toReturn;
    }

    /*
     * This method cyclicly shifts a number by 8 bits to the left and returns the result of that cyclic shift
     */
    private static long cyclicShift(long num){
        String toReturn = String.format("%08x", num); //pad hex string with 0s so its 4 bytes
        toReturn = toReturn.substring(2,toReturn.length()) + toReturn.substring(0,2); //cyclically shift 8 bits
        return Long.parseLong(toReturn,16); //return the result of the cyclic shift (the result is of the datatype "long")
    }

    /*
     * This method xors the values in the "x" array with the values in the "key" array (xoring the same indices in both arrays)
     */
    private static long[] xorWithKey(long x[], long key[]){
        long toReturn[] = new long[x.length];
        for(int i = 0; i < x.length; i++){
            toReturn[i] = x[i] ^ key[i];
        }
        return toReturn;
    }

    /*
     * This method takes in a 2D state array and a key array and xors both of them (both stateArr and key are 128 bits)
     */
    private static long[][] xorStateArrWithKey(long stateArr[][], long key[]){
        long toReturn[][] = new long[stateArr.length][stateArr[0].length];

        long firstHex = -1;
        long secondHex = -1;
        long finalHex = -1;

        for(int i = 0; i < stateArr[0].length; i++){
            for(int j = 0; j < stateArr.length; j++){
                firstHex = (key[i] / 16) % 16; //get second hex value from the right of key[i]
                secondHex = key[i] % 16; //get first hex value from the right of key[i]
                finalHex = (firstHex << 4) | secondHex; //join the two hex values above e.g. firstHex=0x5, secondHex=0x3 so finalHex=0x53
                key[i] = key[i] / 256; //remove the two hex values above from the right-end side of key[i]
                toReturn[stateArr.length-j-1][i] = stateArr[stateArr.length-j-1][i] ^ finalHex; //xor state array bytes with key bytes and store the results in the toReturn array rows and columns they belong to
            }
        }

        return toReturn;
    }

    /*
     * This method is used to make a deep copy of the state array (it returns a deep copy of the state array)
     */
    private static long[][] copyArr(long stateArr[][]){
        long toReturn[][] = new long[stateArr.length][stateArr[0].length];
        for(int i = 0; i < stateArr.length; i++){
            for(int j = 0; j < stateArr[i].length; j++){
                toReturn[i][j] = stateArr[i][j];
            }
        }
        return toReturn;
    }
}
