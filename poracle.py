#!/usr/bin/python3
from random import randint
import threading

RIGHTBYTE=None
class poracle():
    def __init__(self, oracle):
        self.oracle = oracle
        self.block_size = 8
        self.brute_threads = 0

    def make_blocks(self, cipher):
        blocks = []
        for i in range(0, len(cipher), self.block_size):
            blocks.append(cipher[i:(i+self.block_size)])
        return blocks

    def dec_block(self, prev_block, block):
        """
        Provided a block and previous block, this will return what the block
        would be decrypted too.
        """
        prime =  bytearray(self.block_size)  ## random C' prev block
        dec   =  bytearray(self.block_size)  ## decrypted block

        for i in range(self.block_size-1,-1,-1):
            if self.brute_threads >= 1:
                b = self.brute_byte(i, prime+block)
            else:
                print("No threading")
                b = self.brute_byte_slow(i, prime+block)
            dec[i] = ( self.block_size - i ) ^ prev_block[i] ^ b 
            print("byte[%d]: %x dec: %x" % (i,b, dec[i]))

            # set last chars for next padding
            for t in range(self.block_size-1,i-1,-1):
                prime[t] = ( self.block_size+1-i ) ^ dec[t] ^ prev_block[t] 
        return dec

    def single_guess(self, cipher, index, b, mutex):
        global RIGHTBYTE
        self.sem.acquire()
        # make new string b/c threading
        if self.brute_test(mutex): 
            self.sem.release()
            return
        c = bytearray(cipher)
        c[index] = b
        if not self.oracle(c): 
            self.sem.release()
            return
        if index == self.block_size-1:
            c[index-1] = ( c[index-1] + 1 ) % 255
            if self.oracle(c) != True: 
                self.sem.release()
                return
        mutex.acquire()
        if RIGHTBYTE != None: raise Exception("Two right answers?")
        RIGHTBYTE = c[index]
        mutex.release()
        self.sem.release()
        return

    def brute_test(self, mutex):
        ret = False
        mutex.acquire()
        if RIGHTBYTE != None: ret = True
        mutex.release()
        return ret
            
    def brute_byte(self, index, cipher):
        global RIGHTBYTE
        threads = []
        RIGHTBYTE = None
        mutex = threading.Lock()
        self.sem = threading.BoundedSemaphore(self.brute_threads)

        for b in range(255):
            if self.brute_test(mutex): break
            t = threading.Thread(target=self.single_guess, args=(cipher, index, b, mutex))
            threads.append(t)
            t.start()

        for i in threads: i.join() # clean all threads 

        if RIGHTBYTE == None:
            raise Exception("Could not find byte %d" % index)
        ret = RIGHTBYTE
        RIGHTBYTE = None
        return ret
       
    def brute_byte_slow(self, index, cipher):
        """brute force a single byte"""
        # TODO: multi-threaded
        for b in range(256):
            cipher[index] = b
            if self.oracle(cipher) == True: 
                print("[%d:%d] success" % (b, index))
                if index == self.block_size-1:
                    # check we did not get wrong padding. Only matters on the
                    # last byte of block, next round we know last byte will be
                    # 0x2, ect
                    cipher[index-1] = ( cipher[index-1] + 1 ) % 255
                    if self.oracle(cipher) != True: 
                        print("UNTESTED SECOND TRY ENGAGE!!!")
                        continue
                return b
        raise Exception("Could not find byte on index %d" % index)

    def decrypt(self, cipher):
        blocks = self.make_blocks(cipher)
        plain = bytearray(0)
        for i in range(len(blocks)-1, 0, -1):
            plain = self.dec_block(blocks[i-1], blocks[i]) + plain
            print("so far: %s" % self.unpad( plain ))
        return self.unpad(plain)

    def unpad(self, plain):
        p = plain[-1]
        if p > self.block_size:
            raise Exception("Invalid padding: %s" % plain)
        for i in plain[-p:]:
            if i != p: 
                raise Exception("Invalid padding: %s" % plain)
        return plain[:-p]

    def encrypt(self, plain, rblock=None):
        plain = self.pad( bytearray( plain.encode("utf-8") ) )
        blocks = self.make_blocks(plain)
        if rblock == None:
            rblock = bytearray([randint(0,255) for i in range(self.block_size)])
        cipher = rblock
        for i in range(len(blocks)-1, -1, -1):
            c = self.enc_block(blocks[i], cipher[0:self.block_size])
            cipher = c+cipher
        return cipher

    def block_xor(self, a, b):
        if len(a) != self.block_size:
            raise Exception("Invalid lengtth for a: %d" % len(a))
        if len(b) != self.block_size:
            raise Exception("Invalid lengtth for b: %d" % len(b))
        return bytearray([a[i]^b[i] for i in range(self.block_size)])

    def enc_block(self, plain, rblock):
        if type(plain) != bytearray:
            raise Exception("Arg one must be of type <class 'bytearray'> not: %s" % type(plain))
        if len(rblock) != self.block_size:
            raise Exception("len(rblock) == %d != %d == self.block_size" % (len(rblock), self.block_size))
        iv = bytearray([randint(0,255) for i in range(self.block_size)])
        rand_plain = self.dec_block(iv, rblock)

        ### so rand_plain = D(rblock) + iv
        ### xor each side with x:
        ###    (x + rand_plain ) = D(rblock) + (iv + x)
        ### we can chose x = plain + rand_plain
        ###      plain = D(rblock) + (iv + x)
        x = self.block_xor(rand_plain, plain)
        return self.block_xor(iv, x)

    def pad(self, p):
        """
        returns data padded to blocksize
        """
        byte = self.block_size - (len(p) % self.block_size)
        if byte == 0: byte+=8
        return p + bytearray([byte for i in range(byte)])

if __name__ == "main":
    print("swoops")
