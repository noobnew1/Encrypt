from PIL import Image
from string import ascii_uppercase as alphabet
from Crypto.Cipher import AES
import base64
import os

import itertools
import string
import random
import cv2
from cv2 import imread, imwrite
import numpy as np
from base64 import urlsafe_b64encode
from hashlib import md5
from cryptography.fernet import Fernet


# Encryption Algorithm Start from here.
# code For 1st method.
def encrypt1(encryption_data):
    ans1 = str()
    word = encryption_data
    for char in word:
        if((ord(char) >= 65 and ord(char) <= 90) or (ord(char) >= 97 and ord(char) <= 122)):
            if(ord(char) >= 65 and ord(char) <= 90):
                ascii_ = ord(char)-13
                if(ascii_ >= 65 and ascii_ <= 90):
                    ans1 += chr(ascii_)
                else:
                    ascii_change = 91-(65-ascii_)
                    ans1 += chr(ascii_change)
            else:
                # small alphabet
                small_ascii = ord(char)-13
                if(small_ascii >= 90 and small_ascii <= 122):
                    ans1 += chr(small_ascii)
                else:
                    small_ascii_change = 123-(97-small_ascii)
                    ans1 += chr(small_ascii_change)
        else:
            ans1 += char

    return (ans1)


# code For 2nd method.
def encrypt2(plain_text):
    w = 7
    s = str()
    for i in plain_text:
        if ord(i) >= 97 and ord(i) <= 122:
            var = ((ord(i)-97)-w) % 26
            alpha = 97
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        elif ord(i) >= 65 and ord(i) <= 90:
            var = ((ord(i)-65)-w) % 26
            alpha = 65
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        else:
            s += i
    return(s)


# code For 3rd method.
def encrypt3(plain_text):
    w = 17
    s = str()
    for i in plain_text:
        if ord(i) >= 97 and ord(i) <= 122:
            var = ((ord(i)-97)-w) % 26
            alpha = 97
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        elif ord(i) >= 65 and ord(i) <= 90:
            var = ((ord(i)-65)-w) % 26
            alpha = 65
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        else:
            s += i
    return(s)


# code For 4th method.
def codes_table(char):
    table = {
        "A": 11, "B": 21, "C": 31, "D": 41, "E": 51,
        "F": 12, "G": 22, "H": 32, "I": 42, "K": 52,
        "L": 13, "M": 23, "N": 33, "O": 43, "P": 53,
        "Q": 14, "R": 24, "S": 34, "T": 44, "U": 54,
        "V": 15, "W": 25, "X": 35, "Y": 45, "Z": 55, "J": 0,

        11: "A", 21: "B", 31: "C", 41: "D", 51: "E",
        12: "F", 22: "G", 32: "H", 42: "I", 52: "K",
        13: "L", 23: "M", 33: "N", 43: "O", 53: "P",
        14: "Q", 24: "R", 34: "S", 44: "T", 54: "U",
        15: "V", 25: "W", 35: "X", 45: "Y", 55: "Z", 0: "J"
    }

    return (table[char])


def encrypt4(text):
    text, finished_text = text.upper(), ""
    for symbol in text:
        if symbol in alphabet:
            finished_text += str(codes_table(symbol)) + " "

    return (finished_text)


# code For 5th method.
def encrypt5(privateInfo):
    l = []

    BLOCK_SIZE = 16

    PADDING = '{'
    def pad(s): return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    # encrypt with AES, encode with base64
    def EncodeAES(c, s): return base64.b64encode(c.encrypt(pad(s)))
    secret = os.urandom(BLOCK_SIZE)

    cipher = AES.new(secret)
    encoded = EncodeAES(cipher, privateInfo)

    l.append(secret)
    l.append(encoded)
    return(l)


# code For 6th method.
def encrypt6(shift_key, plain_text):
    temp_key = []
    count = 0
    for i in range(len(plain_text)):
        if len(plain_text) <= len(temp_key):
            break
        elif (ord(plain_text[i]) >= 97 and ord(plain_text[i]) <= 122) or (ord(plain_text[i]) >= 65 and ord(plain_text[i]) <= 90):
            temp_key += shift_key[count % len(shift_key)]
            count += 1
        else:
            temp_key += plain_text[i]

    shift_key = ''.join(temp_key)
    s = str()
    for (shift, i) in zip(shift_key, plain_text):
        if ord(i) >= 97 and ord(i) <= 122:
            var = ((ord(i)-97)+(ord(shift)-97)) % 26
            alpha = 97
            for ch in range(0, 26):
                if var == ch:
                    s += (chr(alpha))

                else:
                    alpha += 1
        elif ord(i) >= 65 and ord(i) <= 90:
            var = ((ord(i)-65)+(ord(shift)-65)) % 26
            alpha = 65
            for ch in range(0, 26):
                if var == ch:
                    s += (chr(alpha))
                else:
                    alpha += 1
        else:
            s += i
    return(s)
#  Encryption Algorithm End here.

################################################################


def decrypt1(decryption_data):
    ans1 = str()
    word = decryption_data
    for char in word:
        if((ord(char) >= 65 and ord(char) <= 90) or (ord(char) >= 97 and ord(char) <= 122)):
            # below if is for big alphabet
            if(ord(char) >= 65 and ord(char) <= 90):
                ascii_ = ord(char)+13
                if(ascii_ >= 65 and ascii_ <= 90):
                    ans1 += chr(ascii_)
                else:
                    ascii_change = 64+(ascii_-90)
                    ans1 += (chr(ascii_change))
            else:
                # small alphabet
                small_ascii = ord(char)+13
                if(small_ascii >= 90 and small_ascii <= 122):
                    ans1 += (chr(small_ascii))
                else:
                    small_ascii_change = 96+(small_ascii-122)
                    ans1 += (chr(small_ascii_change))
        else:
            ans1 += char

    return (ans1)


# code For 2nd method.
def decrypt2(plain_text):
    w = 7
    s = str()
    for i in plain_text:
        if ord(i) >= 97 and ord(i) <= 122:
            var = ((ord(i)-97)+w) % 26
            alpha = 97
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        elif ord(i) >= 65 and ord(i) <= 90:
            var = ((ord(i)-65)+w) % 26
            alpha = 65
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        else:
            s += i
    return(s)


# code For 3rd method.
def decrypt3(plain_text):
    w = 17
    s = str()
    for i in plain_text:
        if ord(i) >= 97 and ord(i) <= 122:
            var = ((ord(i)-97)+w) % 26
            alpha = 97
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        elif ord(i) >= 65 and ord(i) <= 90:
            var = ((ord(i)-65)+w) % 26
            alpha = 65
            for ch in range(0, 26):
                if var == ch:
                    s += chr(alpha)
                else:
                    alpha += 1
        else:
            s += i
    return(s)


# code For 4th method.
def codes_table(char):
    table = {
        "A": 11, "B": 21, "C": 31, "D": 41, "E": 51,
        "F": 12, "G": 22, "H": 32, "I": 42, "K": 52,
        "L": 13, "M": 23, "N": 33, "O": 43, "P": 53,
        "Q": 14, "R": 24, "S": 34, "T": 44, "U": 54,
        "V": 15, "W": 25, "X": 35, "Y": 45, "Z": 55, "J": 0,

        11: "A", 21: "B", 31: "C", 41: "D", 51: "E",
        12: "F", 22: "G", 32: "H", 42: "I", 52: "K",
        13: "L", 23: "M", 33: "N", 43: "O", 53: "P",
        14: "Q", 24: "R", 34: "S", 44: "T", 54: "U",
        15: "V", 25: "W", 35: "X", 45: "Y", 55: "Z", 0: "J"
    }

    return table[char]


def decrypt4(text):
    text, finished_text = text.upper(), ""
    for symbol in list(map(int, text.split())):
        finished_text += codes_table(symbol)

    return finished_text


# code For 5th method.
def decrypt5(privateInfo):
    l = []
    BLOCK_SIZE = 16
    PADDING = '{'
    def pad(s): return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    # encrypt with AES, encode with base64
    def EncodeAES(c, s): return base64.b64encode(c.encrypt(pad(s)))
    # generate a randomized secret key with urandom
    secret = os.urandom(BLOCK_SIZE)
    # creates the cipher obj using the key
    cipher = AES.new(secret)
    # encodes you private info!
    encoded = EncodeAES(cipher, privateInfo)
    l.append(secret)
    l.append(encoded)
    return(l)


# code For 6th method.
def decrypt6(shift_key, plain_text):
    temp_key = []
    count = 0
    for i in range(len(plain_text)):
        if len(plain_text) <= len(temp_key):
            break
        elif (ord(plain_text[i]) >= 97 and ord(plain_text[i]) <= 122) or (ord(plain_text[i]) >= 65 and ord(plain_text[i]) <= 90):
            temp_key += shift_key[count % len(shift_key)]
            count += 1
        else:
            temp_key += plain_text[i]

    shift_key = ''.join(temp_key)
    s = str()
    for (shift, i) in zip(shift_key, plain_text):
        if ord(i) >= 97 and ord(i) <= 122:
            var = ((ord(i)-97)-(ord(shift)-97)) % 26
            alpha = 97
            for ch in range(0, 26):
                if var == ch:
                    s += (chr(alpha))
                else:
                    alpha += 1
        elif ord(i) >= 65 and ord(i) <= 90:
            var = ((ord(i)-65)-(ord(shift)-65)) % 26
            alpha = 65
            for ch in range(0, 26):
                if var == ch:
                    s += (chr(alpha))
                else:
                    alpha += 1
        else:
            s += i
    return(s)

# Decryption algorithm end here.
#################################################################


def genData(data):

    # list of binary codes
    # of given data
    newd = []

    for i in data:
        newd.append(format(ord(i), '08b'))
    return newd


def modPix(pix, data):

    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):

        # Extracting 3 pixels at a time
        pix = [value for value in imdata.__next__()[:3] +
               imdata.__next__()[:3] +
               imdata.__next__()[:3]]

        # Pixel value should be made
        # odd for 1 and even for 0
        for j in range(0, 8):
            if (datalist[i][j] == '0') and (pix[j] % 2 != 0):

                if (pix[j] % 2 != 0):
                    pix[j] -= 1

            elif (datalist[i][j] == '1') and (pix[j] % 2 == 0):
                pix[j] -= 1

        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                pix[-1] -= 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]


def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for pixel in modPix(newimg.getdata(), data):

        # Putting modified pixels in the new image
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

# Encode data into image


def encode1(img, hiding_data, new_img_name, upload_folder):
    # img = input("Enter image name(with extension): ")
    img = img
    image = Image.open(img, 'r')

    # data = input("Enter data to be encoded : ")
    data = hiding_data
    if (len(data) == 0):
        raise ValueError('Data is empty')

    newimg = image.copy()
    encode_enc(newimg, data)

    # new_img_name = input("Enter the name of new image(with extension): ")
    new_img_name = new_img_name
    path = os.path.join(upload_folder, new_img_name)
    newimg.save(path)
    return path
    # newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))


# Decode the data in the image
def decode1(img):
    img = img
    image = Image.open(img, 'r')

    data = ''
    imgdata = iter(image.getdata())

    while (True):
        pixels = [value for value in imgdata.__next__()[:3] +
                  imgdata.__next__()[:3] +
                  imgdata.__next__()[:3]]
        # string of binary data
        binstr = ''

        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'

        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0):
            return data


# Returns binary representation of a string
def str2bin(string):
    return ''.join((bin(ord(i))[2:]).zfill(7) for i in string)

# Returns text representation of a binary string


def bin2str(string):
    return ''.join(chr(int(string[i:i+7], 2)) for i in range(len(string))[::7])

# Returns the encrypted/decrypted form of string depending upon mode input


def encrypt_decrypt(string, password, mode='enc'):
    _hash = md5(password.encode()).hexdigest()
    cipher_key = urlsafe_b64encode(_hash.encode())
    cipher = Fernet(cipher_key)
    if mode == 'enc':
        return cipher.encrypt(string.encode()).decode()
    else:
        return cipher.decrypt(string.encode()).decode()


# Encodes secret data in image
def encode2(input_filepath, text, output_filepath, upload_folder, password=None, progressBar=None):
    if password != None:
        # If password is provided, encrypt the data with given password
        data = encrypt_decrypt(text, password, 'enc')
    else:
        data = text
    data_length = bin(len(data))[2:].zfill(32)
    bin_data = iter(data_length + str2bin(data))

    img = imread(input_filepath)
    if img is None:
        raise FileError(
            "The image file '{}' is inaccessible".format(input_filepath))
    height, width = img.shape[0], img.shape[1]
    encoding_capacity = height*width*3
    total_bits = 32+len(data)*7
    if total_bits > encoding_capacity:
        raise DataError("The data size is too big to fit in this image!")
    completed = False
    modified_bits = 0
    progress = 0
    progress_fraction = 1/total_bits

    for i in range(height):
        for j in range(width):
            pixel = img[i, j]
            for k in range(3):
                try:
                    x = next(bin_data)
                except StopIteration:
                    completed = True
                    break
                if x == '0' and pixel[k] % 2 == 1:
                    pixel[k] -= 1
                    modified_bits += 1
                elif x == '1' and pixel[k] % 2 == 0:
                    pixel[k] += 1
                    modified_bits += 1
                if progressBar != None:  # If progress bar object is passed
                    progress += progress_fraction
                    progressBar.setValue(progress*100)
            if completed:
                break
        if completed:
            break

    path = os.path.join(upload_folder, output_filepath)
    written = imwrite(path, img)
    return 0


def decode2(input_filepath, password=None, progressBar=None):
    result, extracted_bits, completed, number_of_bits = '', 0, False, None
    img = imread(input_filepath)

    if img is None:
        raise FileError(
            "The image file '{}' is inaccessible".format(input_filepath))
    height, width = img.shape[0], img.shape[1]
    for i in range(height):
        for j in range(width):
            for k in img[i, j]:
                result += str(k % 2)
                extracted_bits += 1
                if progressBar != None and number_of_bits != None:  # If progress bar object is passed
                    progressBar.setValue(100*(extracted_bits/number_of_bits))
                # If the first 32 bits are extracted, it is our data size. Now extract the original data
                if extracted_bits == 32 and number_of_bits == None:
                    number_of_bits = int(result, 2)*7
                    result = ''
                    extracted_bits = 0
                elif extracted_bits == number_of_bits:
                    completed = True
                    break
            if completed:
                break
        if completed:
            break
    if password == None:
        return bin2str(result)
    else:
        # try:
        return encrypt_decrypt(bin2str(result), password, 'dec')
   # except:
        #raise PasswordError("Invalid password!")

        ########## THE END ###############

###########################################################################
