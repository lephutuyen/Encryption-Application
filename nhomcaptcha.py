#Mã Elgamal
# Tài liệu tham khảo: https://github.com/RyanRiddle/elgamal

#ham tinh x^y(mod p)
def power_mod(x, y, p) : 
    res = 1     # Initialize result
    # Update x if it is more
    # than or equal to p
    x = x % p
     
    if (x == 0) :
        return 0
 
    while (y > 0) :         
        # If y is odd, multiply
        # x with result
        if ((y & 1) == 1) :
            res = (res * x) % p
 
        # y must be even now
        y = y >> 1      # y = y/2
        x = (x * x) % p
    return res

# Ham tim nghich dao tren vanh
def mod_inverse(x,m):
    for n in range(m):
        if (x * n) % m == 1:
            return n
            break
        elif n == m - 1:
            return "Null"
        else:
            continue

def encrypt_El(m, p, a, x, k):
    y1 = power_mod(a,k,p)
    y2 = (m*pow(power_mod(a,x,p),k))%p
    return(y1,y2)

#DECRYPTION
#c(c1,c2)
def decrypt_El(c1,c2,p,x):
    # Tinh khoa K
    k=power_mod(c1,x,p)
    #knd la nghich dao cua k
    knd = mod_inverse(k,p)
    m=(c2*knd)%p
    return m

# MA RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
def encrypt_RSA(plaintext):
    # Tao khoa cong khai va khoa bi mat bang cach su dung RSA 2048
    keyPair = RSA.generate(2048)
    #<_RSAobj @0x262fac5d940 n(2048),e,d,p,q,u,private>
    # keyPair bao gom: e,d,p,q,u,private
    
    #keyPair.n.bit_length()
    
    # pubKey la khoa cong khai gom: m, e và n(N)
    pubKey = keyPair.publickey()
    # keyPair.n giong voi pubKey.n deu la N
    #print(f"Public key: (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    
    #pubKeyPEM = pubKey.exportKey()
    #print(pubKeyPEM.decode('ascii'))
    
    #print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    #privKeyPEM = keyPair.exportKey()
    #print(privKeyPEM.decode('ascii'))
    
    msg = bytes(str(plaintext), 'utf-8')
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(msg)
    return hex(pubKey.n), hex(keyPair.d), hex(pubKey.e), binascii.hexlify(encrypted)

# Do su dung lop co san de tao khoa nen khong co qua trinh giai ma
def decrypt_RSA(encrypted):
    keyPair = RSA.generate(2048)
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(encrypted)
    return decrypted.decode('utf-8')

# CÁC HỆ MÃ KHỐI
# Mã DES
import random

# Đổi từng số sang hệ Hex
def inttohex(n):
    mp = { 0 : "0",
           1 : "1",
           2 : "2",
           3 : "3",
           4 : "4",
           5 : "5",
           6 : "6",
           7 : "7",
           8 : "8",
           9 : "9",
           10 : "A",
           11 : "B",
           12 : "C",
           13  : "D",
           14 : "E",
           15 : "F" }
    return mp[n]

# Tạo key ngẫu nhiên
def makeKey():
    key=''
    for i in range(16):
        tmp=random.randint(0,15)
        key=key+inttohex(tmp)
    return key

# Đổi Thập lục sang Nhị phân
def hex2bin(s):
    mp = {'0' : "0000",
          '1' : "0001",
          '2' : "0010",
          '3' : "0011",
          '4' : "0100",
          '5' : "0101",
          '6' : "0110",
          '7' : "0111",
          '8' : "1000",
          '9' : "1001",
          'A' : "1010",
          'B' : "1011",
          'C' : "1100",
          'D' : "1101",
          'E' : "1110",
          'F' : "1111" }
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]        
    return bin

# Đổi Nhị phân sang Thập lục
def bin2hex(s):
    mp = {"0000" : '0',
          "0001" : '1',
          "0010" : '2',
          "0011" : '3',
          "0100" : '4',
          "0101" : '5',
          "0110" : '6',
          "0111" : '7',
          "1000" : '8',
          "1001" : '9',
          "1010" : 'A',
          "1011" : 'B',
          "1100" : 'C',
          "1101" : 'D',
          "1110" : 'E',
          "1111" : 'F' }
    hex = ""
    for i in range(0,len(s),4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]        
    return hex

# Đổi Nhị phân sang Thập phân
def bin2dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal

# Đổi Thập phân sang Nhị phân
def dec2bin(num):
    res = bin(num).replace("0b", "")
    if(len(res)%4 != 0):
        div = len(res) / 4
        div = int(div)
        counter =(4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

# Hàm hoán vị
def permute(k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation

# Hàm dịch vòng trái
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1,len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

# Tính xor hai chuỗi nhị phân số a và b
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

# Bảng hoán vị đầu IP
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Hàm mở rộng Expansion
exp_d = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5,
         6 , 7 , 8 , 9 , 8 , 9 , 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1 ]

# Hoán vị P (của hàm Feistel)
per = [ 16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25 ]

# Bảng S-box
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]],
         
         [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]],
          
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
         
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]],
         
        [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ],
         
         [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ],
          
         [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
           [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
           [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
           [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] ]
         
# Bảng hoán vị cuối FP
final_perm = [ 40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25 ]

def encrypt(pt, rkb, rk):
    pt = hex2bin(pt)
    
    # Hoán vị đầu
    pt = permute(pt, initial_perm, 64)
    #print("After initial permutation", bin2hex(pt))
    
    # Phân chia thành nửa trái và nửa phải
    left = pt[0:32]
    right = pt[32:64]
    for i in range(0, 16):
        # Nửa phải qua hàm mở rộng (32 thành 48)
        right_expanded = permute(right, exp_d, 48)
        # XOR RoundKey[i] và right_expanded
        xor_x = xor(right_expanded, rkb[i])
        
        # Qua S-boxex
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] +xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = sbox[j][row][col]
            sbox_str = sbox_str + dec2bin(val)
            
        # Hoán vị P
        sbox_str = permute(sbox_str, per, 32)
        
        # XOR left và sbox_str
        result = xor(left, sbox_str)
        left = result
        
        # Đỗi chỗ (vòng lặp cuối)
        if(i != 15):
            left, right = right, left
        #print("Round ", i + 1, " ", bin2hex(left), " ",bin2hex(right), " ", rk[i])
        
        # Kết hợp nửa trái và nửa phải lại
        combine = left + right
        
        # Hoán vị cuối FP
        cipher_text = permute(combine, final_perm, 64)
    return cipher_text
    
#pt = "0123456789ABCDEF"
#key = "133457799BBCDFF0"
def cv_lq_key(key):
    # Sinh khóa
    key = hex2bin(key)
    
    # Bảng PC1
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4 ]

    # Qua bảng PC1 lấy 56 bit từ 64 bit của khóa
    key = permute(key, keyp, 56)

    # Số lượng bit dịch vòng
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1 ]

    # Bảng PC2: Nén 56 bit thành 48 bit
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32 ]

    # Phân chia khóa thành nửa trái nửa phải
    left = key[0:28] # rkb for RoundKeys in binary
    right = key[28:56] # rk for RoundKeys in hexadecimal

    rkb = []
    rk = []
    for i in range(0, 16):
        # Dịch vòng trái theo số lượng bit của vòng
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        
        # Kết hợp nủa trái và phải
        combine_str = left + right
        
        # Qua PC2: Nén 56 bit thành 48 bit
        round_key = permute(combine_str, key_comp, 48)
        
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
    return rkb, rk

#MA HILL
import numpy as np

def encrypt_Hill(msg):
	msg=msg.replace(" ","") #Thay the khoang trang
	K=make_key()			#Tao va kiem tra khoa
	len_check=len(msg)%2==0
	if not len_check:
		msg+="0"
	P = create_matrix_of_integers_from_string(msg) 
	msg_len=int(len(msg)/2)
	encrypted_msg=""
	for i in range(msg_len):
		row_0=P[0][i]*K[0][0]+P[1][i]*K[1][0]
		integer=int(row_0%26 +65)
		encrypted_msg+=chr(integer)
		row_1=P[0][i]*K[0][1]+P[1][i]*K[1][1]
		integer=int(row_1%26 +65)
		encrypted_msg+=chr(integer)
	return encrypted_msg

def decrypt_Hill(encrypted_msg):
    K = make_key()
    
    #TINH DINH THUC
    determinant = K[0][0]*K[1][1]-K[0][1]*K[1][0]
    determinant = determinant%26
    
    #Tinh nghich dao cua dinh thuc
    multiplicative_inverse = find_multiplicative_inverse(determinant)
    
    #Tinh ma tran PHU HOP cua khoa K
    K_inverse = K
    K_inverse[0][0],K_inverse[1][1] = K_inverse[1][1],K_inverse[0][0]
    K_inverse[0][1] *=-1
    K_inverse[1][0] *=-1
    for row in range(2):
        for column in range(2):
            K_inverse[row][column] *= multiplicative_inverse
            K_inverse[row][column] = K_inverse[row][column]%26
            
    #Tach cipher text
    C = create_matrix_of_integers_from_string(encrypted_msg)
    msg_len = int(len(encrypted_msg)/2)
    decrypted_msg=""
    for i in range(msg_len): #Giai ma C*K-1
        column_0 = C[0][i] * K_inverse[0][0] + C[1][i] * K_inverse[1][0]
        integer=int(column_0%26 +65)
        decrypted_msg+=chr(integer)
        column_1 = C[0][i] * K_inverse[0][1] + C[1][i] * K_inverse[1][1]
        integer=int(column_1%26 +65)
        decrypted_msg+=chr(integer)
    if decrypted_msg[-1] == "0":
        decrypted_msg = decrypted_msg[:-1]
    return decrypted_msg
        
def make_key(): # Tạo và kiểm tra khóa
    determinant = 0
    K = None
    while True:
        KEY=box.get(2.0,"3.0 -1c")
        KEY = KEY.replace(" ","")
        K = create_matrix_of_integers_from_string(KEY)
        determinant = K[0][0]*K[1][1]-K[0][1]*K[1][0]
        determinant = determinant%26
        inverse_element = find_multiplicative_inverse(determinant)
        if inverse_element==-1:
            tmp="Determinant is not relatively prime to 26, univertible key"
            box1.insert(END,tmp+'\n')
        #Nguyen ban la and thay or
        elif np.amax(K)>26 or np.amin(K)<0:
            tmp="Only a-z characters are accepted"
            box1.insert(END,tmp+'\n')
        else:
            break
    return K

def find_multiplicative_inverse(determinant): #Tim nghich dao dinh thuc
    multiplicative_inverse = -1
    for i in range(26):
        inverse = determinant*i
        if inverse%26 == 1:
            multiplicative_inverse=i
            break;
    return multiplicative_inverse

def create_matrix_of_integers_from_string(string): # Tao ma tran khoa
    integers = [chr_to_int(c) for c in string]
    length = len(integers)
    M = np.zeros((2,int(length/2)),dtype=np.int32)
    iterator=0
    for column in range(int(length/2)):
        for row in range (2):
            M[row][column] = integers[iterator]
            iterator+=1
    return M

def chr_to_int(char):
    char=char.upper()
    integer = ord(char)-65
    return integer

#MA AFFINE
def mod_inverse(x,m):
    for n in range(m):
        if (x * n) % m == 1:
            return n
            break
        elif n == m - 1:
            return "Null"
        else:
            continue
        
DIE = 26
#THEO CODE CU ->LOI
#TypeError: not all arguments converted during string formatting
#KEY = (7,3, mod_inverse(7,26))        
def encryptChar(char):
    K1=box.get(2.0,"3.0 -1c")
    K1=int(K1)
    K2=box.get(3.0,"4.0 -1c")
    K2=int(K2)
    KI = mod_inverse(K1,26)
    if (char.isupper()):
        return chr((K1 * (ord(char)-65) + K2) % DIE + 65)
    else: return chr((K1 * (ord(char)-97) + K2) % DIE + 97)

def encrypt_Affine(string):
    str = ''
    for char in string:
        str += encryptChar(char)
    return str
    
def decryptChar(char):
    K1=box.get(2.0,"3.0 -1c")
    K1=int(K1)
    K2=box.get(3.0,"4.0 -1c")
    K2=int(K2)
    KI = mod_inverse(K1,26)
    if (char.isupper()):
        return chr(KI * ((ord(char)-65) - K2) % DIE + 65)
    else: return chr(KI * ((ord(char)-97) - K2) % DIE + 97)
    
def decrypt_Affine(string):
    str = ''
    for char in string:
        str += decryptChar(char)
    return str 

#MA DOI CHO
def split_len(seq,length):
	return [seq[i:i +length] for i in range(0,len(seq),length)]

def encrypt_dC(plaintext,key):
	plaintext=plaintext.replace(" ","")
	order={
		int(val): num for num, val in enumerate(key)
	}
	ciphertext=''
	for index in sorted(order.keys()):
		for part in split_len(plaintext,len(key)):
			try:ciphertext+=part[order[index]]
			except IndexError:
				continue
	return ciphertext

def decrypt_dC(ciphertext,key):
	ciphertext=ciphertext.replace(" ","")
	order={
		int(val): num for num, val in enumerate(key)
	}
	plaintext=''
	n=int(len(ciphertext)/len(key))
	for index in sorted(order.keys()):
		for part in split_len(ciphertext,n):
			try:plaintext+=part[order[index]]
			except IndexError:
				continue
	return plaintext

#MA THAY THE DON
import random

LETTERS='ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt_tTD(message,key):
	translated=''
    #LETTERS là hằng chứa bảng chữ cái
	charsA=LETTERS
	charsB=key
	for symbol in message:
		if symbol.upper() in charsA:
			symIndex=charsA.find(symbol.upper())
			if symbol.isupper():
				translated+=charsB[symIndex].upper()
			else:
				translated+=charsB[symIndex].lower()
		else:
			translated+=symbol
	return translated

def decrypt_tTD(message,key):
	translated=''
	charsB=LETTERS
	charsA=key
	for symbol in message:
		if symbol.upper() in charsA:
			symIndex=charsA.find(symbol.upper())
			if symbol.isupper():
				translated+=charsB[symIndex].upper()
			else:
				translated+=charsB[symIndex].lower()
		else:
			translated+=symbol
	return translated

def getRandomKey():
	randomList=list(LETTERS)
	random.shuffle(randomList)
	return ''.join(randomList)

#MA CAESAR
def encrypt_Caesar(text,k):
	text=text.replace(" ","")
	result=""
	for i in range(len(text)):
		char=text[i]
		if(char.isupper()):
			result+=chr((ord(char)+k-65) % 26 +65)
		else:
			result+=chr((ord(char)+k-97) % 26 +97)
	return result

def decrypt_Caesar(text,k):
	text=text.replace(" ","")
	result=""
	for i in range(len(text)):
		char=text[i]
		if(char.isupper()):
			result+=chr((ord(char)-k-65) % 26 +65)
		else:
			result+=chr((ord(char)-k-97) % 26 +97)
	return result

#MA VIGENERE
def encrypt_Vigenere(plaintext,key):
	key_length=len(key)
	key_as_int=[ord(i) for i in key]
	plaintext_int=[ord(i) for i in plaintext]
	ciphertext=''
	for i in range(len(plaintext_int)):
		value=(plaintext_int[i]+key_as_int[i%key_length])%26
		ciphertext+=chr(value+65)
	return ciphertext

def decrypt_Vigenere(ciphertext,key):
	key_length=len(key)
	key_as_int=[ord(i) for i in key]
	ciphertext_int=[ord(i) for i in ciphertext]
	plaintext=''
	for i in range(len(ciphertext_int)):
		value=(ciphertext_int[i]-key_as_int[i%key_length])%26
		plaintext+=chr(value+65)
	return plaintext

#MA DAO NGUOC
def encrypt_ReverseCipher(message):
	i=len(message)-1;
	translated=''
	while  i>=0:
		translated=translated+message[i]
		i=i-1
	return translated

def decrypt_ReverseCipher(translated):
	i=len(translated)-1;
	decrypted=''
	while  i>=0:
		decrypted=decrypted+translated[i]
		i=i-1
	return decrypted

#
from tkinter import *
#from tkinter.ttk import *

from PIL import Image,ImageTk

#Tạo Tk window
root = Tk()
root.title('Captcha')
root.geometry("896x630")
root.iconbitmap(r'Captcha.ico')
load = Image.open('bg.jpg')
#Xuat anh
render = ImageTk.PhotoImage(load)
#Hien thi anh
Img=Label(root,image=render)
#Vi tri toa do
Img.place(x = 0,y = 0)

name=Label(root,text="MA HOA - GIAI MA",fg='#ffffff',bg='#14296A',bd=0)
name.config(font=("Optima",30))
name.place(x=440,y=20)

#Input
inp=Label(root,text="INPUT",fg='#ffffff',bg='#14296A',bd=0)
inp.config(font=("Courier",12))
inp.place(x=350,y=100)
#Output
out=Label(root,text="OUTPUT",fg='#ffffff',bg='#14296A',bd=0)
out.config(font=("Courier",12))
out.place(x=350,y=400)

box=Text(root,width=45,height=8,font=("Times",16))
#Cach doi tuong tren
box.place(x=350,y=130)

box1=Text(root,width=45,height=8,font=("Times",16))
box1.place(x=350,y=430)
button_frame=Frame(root).pack(side=BOTTOM)

def clear():
    box.delete(1.0,END)
    box1.delete(1.0,END)
    
def submit():
    box1.delete(2.0,"end-1c")
    #Doc hema
    hema=machoosen.get()
    chiso=machoosen.current()
    #Doc qua trinh
    qt=qtchoosen.get()
    soqt=qtchoosen.current()
        
    if soqt==0:# ma hoa
        tmp="Cyphertext"
        box1.insert(END,tmp+': ')
        if chiso==0:
            p=box.get(1.0,"2.0 -1c")
            k=box.get(2.0,"3.0 -1c")
            c=encrypt_Vigenere(p,k)
            box1.insert(END,c+'\n')
        elif chiso==1:
            p=box.get(1.0,"2.0 -1c")
            c=encrypt_ReverseCipher(p)
            box1.insert(END,c+'\n')
        elif chiso==2:
            p=box.get(1.0,"2.0 -1c")
            k=box.get(2.0,"3.0 -1c")
            k=int(k)
            c=encrypt_Caesar(p,k)
            box1.insert(END,c+'\n')
        elif chiso==3:
            p=box.get(1.0,"2.0-1c")
            k=box.get(2.0,"3.0-1c")
            if k=='':
                k=getRandomKey()
            c=encrypt_tTD(p,k)
            box1.insert(END,c+'\n')
            key='Key: '+k
            box1.insert(END,key+'\n')
        elif chiso==4:
            p=box.get(1.0,"2.0 -1c")
            k=box.get(2.0,"3.0 -1c")
            c=encrypt_dC(p,k)
            box1.insert(END,c+'\n')
        elif chiso==5:
            p=box.get(1.0,"2.0 -1c")
            c=encrypt_Affine(p)
            box1.insert(END,c+'\n')
        elif chiso==6:
            p=box.get(1.0,"2.0 -1c")
            c=encrypt_Hill(p)
            box1.insert(END,c+'\n')
        elif chiso==7:
            p=box.get(1.0,"2.0-1c")
            key=box.get(2.0,"3.0-1c")
            if p=='':
                p=makeKey()
                randomp=1
            if key=='':
                key=makeKey()
            rkb, rk=cv_lq_key(key)
            c=bin2hex(encrypt(p, rkb, rk))
            box1.insert(END,c+'\n')
            # In Plaintext neu su dung random
            if randomp:
                cyphertext="Plaintext: "+p
                box1.insert(END,cyphertext+'\n')
            k='Key: '+key
            box1.insert(END,k+'\n')
        elif chiso==8:
            p=box.get(1.0,"2.0-1c")
            n, d, e, c = encrypt_RSA(p)
            c=str(c)
            box1.insert(END,c+'\n')
            publKey=f"Public key:\n(n={n},\ne={e})\n\n"
            priKey=f"Private key:\n(n={n},\nd={d})"
            tmp=publKey+priKey
            box1.insert(END,tmp+'\n')            
        else:
            p=box.get(1.0,"2.0 -1c")
            p=int(p)
            m=box.get(2.0,"3.0 -1c")
            m=int(m)
            a=box.get(3.0,"4.0 -1c")
            a=int(a)
            x=box.get(4.0,"5.0 -1c")
            x=int(x)
            k=box.get(5.0,"6.0 -1c")
            k=int(k)
            c=encrypt_El(m,p,a,x,k)
            c=str(c)
            box1.insert(END,c+'\n')
            
    if soqt==1:# giai ma
        tmp="Plaintext"
        box1.insert(END,tmp+': ')
        if chiso==0:
            p=box.get(1.0,"2.0-1c")
            k=box.get(2.0,"3.0-1c")
            c=decrypt_Vigenere(p,k)
            box1.insert(END,c+'\n')
        elif chiso==1:
            p=box.get(1.0,"2.0 -1c")
            c=decrypt_ReverseCipher(p)
            box1.insert(END,c+'\n')
        elif chiso==2:
            p=box.get(1.0,"2.0 -1c")
            k=box.get(2.0,"3.0 -1c")
            k=int(k)
            c=decrypt_Caesar(p,k)
            box1.insert(END,c+'\n')
        elif chiso==3:
            p=box.get(1.0,"2.0-1c")
            k=box.get(2.0,"3.0-1c")
            if k=='':
                k=getRandomKey()
            c=decrypt_tTD(p,k)
            box1.insert(END,c+'\n')
            key='Key: '+k
            box1.insert(END,key+'\n')
        elif chiso==4:
            p=box.get(1.0,"2.0 -1c")
            k=box.get(2.0,"3.0 -1c")
            c=decrypt_dC(p,k)
            box1.insert(END,c+'\n')
        elif chiso==5:
            p=box.get(1.0,"2.0 -1c")
            c=decrypt_Affine(p)
            box1.insert(END,c+'\n')
        elif chiso==6:
            p=box.get(1.0,"2.0 -1c")
            c=decrypt_Hill(p)
            box1.insert(END,c+'\n')
        elif chiso==7:
            p=box.get(1.0,"2.0-1c")
            key=box.get(2.0,"3.0-1c")
            if p=='':
                p=makeKey()
                randomp=1
            if key=='':
                key=makeKey()
            rkb, rk=cv_lq_key(key)
            rkb_rev = rkb[::-1]
            rk_rev = rk[::-1]
            c = bin2hex(encrypt(p, rkb_rev, rk_rev))
            box1.insert(END,c+'\n')
            # In cyphertextt neu su dung random
            if randomp:
                plaintext="Cyphertext: "+p
                box1.insert(END,plaintext+'\n')
            k='Key: '+key
            box1.insert(END,k+'\n')
        elif chiso==8:
            thongbao='  Không có quá trình giải mã\n  Do sử dụng lớp có sẵn để tạo khóa'
            box1.insert(END,thongbao+'\n')
        else:
            c1=box.get(1.0,"2.0 -1c")
            c1=int(c1)
            c2=box.get(2.0,"3.0 -1c")
            c2=int(c2)
            p=box.get(3.0,"4.0 -1c")
            p=int(p)
            x=box.get(4.0,"5.0 -1c")
            x=int(x)
            c=decrypt_El(c1,c2,p,x)
            c=str(c)
            box1.insert(END,c+'\n')

clear_button=Button(button_frame, text="clear text", font=(("Times"),12,"bold"), bg='#303030',fg="#ffffff",command=clear)
submit_button=Button(button_frame, text="Submit", font=(("Times"),12,"bold"), bg='#303030',fg="#ffffff",command=submit)
clear_button.place(x=500,y=350)
submit_button.place(x=700,y=350)

gioithieu=Label(root,text="Mời chọn mã",fg='#ffffff',bg='#14296A',bd=0)
gioithieu.config(font=("Times",12))
gioithieu.place(x=10,y=100)

gioithieu1=Label(root,text="\nBẢNG HƯỚNG DẪN:\n\nBước 1: Chọn hệ mã\t\t\t\nBước 2: Chọn quá trình\t\t\t\nBước 3: Nhấn OK\t\t\t\t\nBước 4: Làm theo yêu cầu trong khung OUTPUT\n*Lưu ý nhập Input:\t\t\t\t\n  - Plaintext và Cyphertext in hoa và viết liền (nếu có)\n- Kết thúc dòng bằng Enter\t\t\t\n",bg='#303030',fg="#ffffff",bd=0)
gioithieu1.config(font=("Curier",11))
gioithieu1.place(x=5,y=430)

#Label sau dong nay khong hoat dong loi option -fg
from tkinter.ttk import *

# Combobox creation
n =StringVar()
machoosen =Combobox(root, width = 27, textvariable = n,font=("Times",12))
 
# Adding combobox drop down list
machoosen['values'] = (' Mã Vigenere', 
                          ' Mã đảo ngược',
                          ' Mã Caesar',
                          ' Mã thay thế đơn',
                          ' Mã đổi chỗ',
                          ' Mã Affine',
                          ' Mã Hill',
                          ' Mã DES',
                          ' Mã RSA',
                          ' Mã Elgamal')
  
machoosen.place(x=10,y=130)

from tkinter import *
gioithieu1=Label(root,text="Mời chọn quá trình",fg='#ffffff',bg='#14296A',bd=0)
gioithieu1.config(font=("Times",12))
gioithieu1.place(x=10,y=270)

#Label sau dong nay khong hoat dong loi option -fg
from tkinter.ttk import *

# Combobox creation
n =StringVar()
qtchoosen =Combobox(root, width = 27, textvariable = n,font=("Times",12))
 
# Adding combobox drop down list
qtchoosen['values'] = (' Mã hóa', 
                          ' Giải mã')
  
qtchoosen.place(x=10,y=300)

from tkinter import *

def ok():
    hema=machoosen.get()
    chiso=machoosen.current()
   
    qt=qtchoosen.get()
    soqt=qtchoosen.current()
    
    box1.insert(END,hema+' - ')
    box1.insert(END,qt+'\n')

    if soqt==0:
        tmp='Plaintext'
    else:
        tmp='Cyphertext'
    
    # Do bo qua qua trinh ma hoa he ma RSA    
    if (chiso!=8):
        yc='Yêu cầu nhập theo thứ tự sau vào khung INPUT:\n- Dòng 1: '
        box1.insert(END,yc)
        
    if chiso==0:
        tmp=tmp+'\n- Dòng 2: Key\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==1:
        tmp=tmp+'\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==2:
        tmp=tmp+'\n- Dòng 2: Khóa K\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==3:
        tmp=tmp+'\n- Dòng 2: Khóa K (Nhập 26 chữ cái)\n  Nếu sử dụng random key thì bỏ qua dòng 2\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==4:
        tmp=tmp+'\n- Dòng 2: Khóa K (Nhập chuỗi số)\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==5:
        tmp=tmp+'\n- Dòng 2: a (k=(a,b))\n- Dòng 3: b (k=(a,b))\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==6:
        tmp=tmp+'\n- Dòng 2: Key (Nhập 4 ký tự cách nhau)\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==7:
        tmp=tmp+f' (Nhập chuỗi 16 ký tự thuộc hệ Hex)\n- Dòng 2: Key (Nhập chuỗi 16 ký tự thuộc hệ Hex)\n\n  Nếu sử dụng random key thì bỏ qua dòng 2\n  Nếu random key, random {tmp} thì bỏ qua INPUT\n  Sau đó nhấn Submit'
        box1.insert(END,tmp+'\n')
    elif chiso==8:
        if(soqt==1):
            thongbao='  Không có quá trình giải mã\n  Do sử dụng thư viện có sẵn để tạo khóa'
            box1.insert(END,thongbao+'\n')
        else:
            yc='Yêu cầu nhập theo thứ tự sau vào khung INPUT:\n- Dòng 1: '
            box1.insert(END,yc)
            tmp=tmp+'\n  Sau đó nhấn Submit'
            box1.insert(END,tmp+'\n')
    else:
        if(soqt==0):
            tmp='p (số nguyên tố)\n- Dòng 2: M (thông điệp thuộc Zp)\n- Dòng 3: a (số nguyên nhỏ hơn p)\n- Dòng 4: x (số nguyên nhỏ hơn p)\n- Dòng 5: k (số nguyên nhỏ hơn p)\n  Sau đó nhấn Submit'
            box1.insert(END,tmp+'\n')
        else:
            tmp='C1\n- Dòng 2: C2\n- Dòng 3: p\n- Dòng 4: x (số nguyên nhỏ hơn p)\n  Sau đó nhấn Submit'
            box1.insert(END,tmp+'\n')

ok_button=Button(button_frame, text="OK", font=(("Times"),12,"bold"), bg='#303030',fg="#ffffff",command=ok)
ok_button.place(x=250,y=300)

root.mainloop()