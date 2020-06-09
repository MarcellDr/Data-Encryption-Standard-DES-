from tables import *
import re


# listOfBit != byte
# byte = '10001010' (string)
# listOfBit = [1, 0, 0, 0, 1, 0, 1, 0] (list of integer)
# listOfBit is a byte that has been converted into a list of integer

def encrypt(key, text):
    if(len(key) < 16):  # we're going to use HEX value as key, and it must be 8 values
        raise Exception('Key must be 8 HEX values')
    else:
        key = key[:16] # if there's more than 8 values, just take the first 8 HEX
    while(len(text) % 8 != 0): #DES encryption can only process 8 letters || 64 bits at once
        text += '#' # add '#' to the text so it can have size multiple of 8

    subKeys = createSubKeys(key) #generate subkey from key input
    textBlock = split(text, 8) #split text into textblock that each block consist of 8 letters
    result = list()
    for block in textBlock: # process block one by one
        listOfBitText = stringToBit(block) # convert block into their representative list of bit
        IPpermutated = permutate(listOfBitText, IPtable) # first permutation w/ IP table
        left, right = split(IPpermutated, 32) # split half of the list into 2 sections
        for i in range(16):
            rightExpand = permutate(right, EPtable) # expand right using permutation w/ EP table
            rightXOR = XOR(subKeys[i], rightExpand) # XOR it w/ subkey[i] (start from the first)
            rightSubstitute = substitute(rightXOR) # sBOX method
            Ppermutated = permutate(rightSubstitute, Ptable) # another permutation
            temp = XOR(left, Ppermutated) # XOR left w/ the last permutation
            left = right # switch left w/ the unprocessed right
            right = temp # switch right w/ temp
        finalPermutation = permutate(right+left, FPtable) # merge right w/ left then permutate it w/ FP table
        result += finalPermutation # store each final permutation of the processed block
    encryptedText = bitToHEX(result) # make result's list of bit into HEX value
    return encryptedText 


def decrypt(key, encryptedText):
    if(len(key) < 16): # we're going to use HEX value as key, and it must be 8 values
        raise Exception('Key must be 8 HEX values')
    else:
        key = key[:16] # if there's more than 8 values, just take the first 8 HEX
    if(len(encryptedText) < 16): #through encryption process, the encrypted text must have size multiple of 8
        raise Exception('EncryptedText size must be multiple of 8 HEX values')

    subKeys = createSubKeys(key) #generate subkey from key input
    HEXBlock = split(encryptedText, 16) #split encryptedText into HEXblock that each block consist of 8 HEX value
    result = list()
    for block in HEXBlock: # process block one by one
        listOfBitText = HEXToBit(block) # convert block into their representative list of bit
        IPpermutated = permutate(listOfBitText, IPtable) # first permutation w/ IP table
        left, right = split(IPpermutated, 32) # split half of the list into 2 sections
        for i in range(16):
            rightExpand = permutate(right, EPtable) # expand right using permutation w/ EP table
            rightXOR = XOR(subKeys[15-i], rightExpand) # XOR it w/ subkey[15-i] (start from the last)
            rightSubstitute = substitute(rightXOR) # sBOX method
            PFpermutated = permutate(rightSubstitute, Ptable) # another permutation
            temp = XOR(left, PFpermutated) # XOR left w/ the last permutation
            left = right # switch left w/ the unprocessed right
            right = temp # switch right w/ temp
        finalPermutation = permutate(right+left, FPtable) # merge right and left then permutate it w/ FP table
        result += finalPermutation # store each final permutation of the processed block
    finalResult = bitToString(result) # turn list of bit into text
    finalResult = re.findall(r'.*?(?=#*$)', finalResult)[0] # because we add '#' when encrypted the text, remove it all w/ regex
    return finalResult


def createSubKeys(key): # generate subkey
    def shift(left, right, n): # method for shifting bitwise left n step
        return left[n:] + left[:n], right[n:] + right[:n]
    shiftStepRules = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
    subKeys = 16*[[None]*8] # initiate 16 subkeys
    listOfBit = HEXToBit(key) # convert HEX value into their representative list of bit
    PC1permutated = permutate(listOfBit, PC1table) # permutate list w/ PC1 table
    left, right = split(PC1permutated, 28) # split half of the list into 2 sections
    for i in range(16):
        left, right = shift(left, right, shiftStepRules[i]) # shifting bit inside left and right
        subKeys[i] = permutate(left+right, PC2table) # get the subkey through permutate merged left and right w/ PC2 table
    return subKeys


def split(array, n): # split array or list into their sub-sections of size 'n'
    return [array[i:i+n] for i in range(0, len(array), n)]


def stringToBit(text): # convert text into their representative list of bit
    listOfBit = list()
    for char in text: # loop through each char inside text
        byte = charToByte(char) # get the char value on one byte
        listOfBit.extend([int(bit) for bit in list(byte)]) # store each bit of the byte into list of bit
    return listOfBit


def HEXToBit(key): # convert HEX value into their representative list of bit
    listOfBit = list()
    for HEX in split(key, 2): # loop through each HEX inside key
        byte = HEXToByte(HEX) # get the HEX value on one byte
        listOfBit.extend([int(bit) for bit in list(byte)]) # store each bit of the byte into list of bit
    return listOfBit


def bitToString(listOfBit): # turn back list of bit into text
    return ''.join(chr(int(value, 2)) for value in [''.join([str(bit) for bit in byte]) for byte in split(listOfBit, 8)])


def bitToHEX(listOfBit): # turn back list of bit into HEX value
    return ''.join(hex(int(value, 2))[2:] if (len(hex(int(value, 2))[2:]) == 2) else '0' + hex(int(value, 2))[2:]
                   for value in [''.join([str(bit) for bit in byte]) for byte in split(listOfBit, 8)])


def charToByte(char, bitSize=8): # get the char value on one byte
    byte = bin(char)[2:] if isinstance(char, int) else bin(ord(char))[2:]
    while(len(byte) != bitSize):
        byte = '0' + byte
    return byte


def HEXToByte(HEX): # get the HEX value on one byte
    byte = bin(int(HEX, 16))[2:]
    while(len(byte) != 8):
        byte = '0' + byte
    return byte


def permutate(listOfBit, table): # permutate method of the given list of bit using the given table
    return [listOfBit[i-1] for i in table]


def XOR(listOfBit1, listOfBit2): # Apply XOR for the 2 given listOfBit
    return [x ^ y for x, y in zip(listOfBit1, listOfBit2)]


def substitute(listOfBit): # sBOX method
    result = list()
    subLists = split(listOfBit, 6) # split listOfBit into sublists of size 6
    for i in range(len(subLists)): # loop through all of the sublist
        subList = subLists[i]
        row = int(str(subList[0])+str(subList[5]), 2) # get row from first and last bit of the sublist
        column = int(''.join([str(x) for x in subList[1:][:-1]]), 2) # get column from the rest bits of the sublist
        value = sBox[i][row][column] # get sBOX value for the given row and column
        binaryValue = charToByte(value, 4) # get the char value on one byte
        result += [int(x) for x in binaryValue] # store each bit of the byte into list of bit
    return result


def viewBit(listOfBit): # method to see the byte of the given listOfBit
    stringBit = ''
    for byte in split(listOfBit, 8):
        for bit in byte:
            stringBit += str(bit)
        stringBit += ' '
    return stringBit
