#! /usr/bin/env python2

#
# Copyright (C) Telecom ParisTech
# 
# This file must be used under the terms of the CeCILL. This source
# file is licensed as described in the file COPYING, which you should
# have received as part of this distribution. The terms are also
# available at:
# http://www.cecill.info/licences/Licence_CeCILL_V1.1-US.txt
#

import sys
import argparse

import des
import km
import numpy

def main ():
    # ************************************************************************
    # * Before doing anything else, check the correctness of the DES library *
    # ************************************************************************
    if not des.check ():
        sys.exit ("DES functional test failed")

    # *************************************
    # * Check arguments and read datafile *
    # *************************************
    argparser = argparse.ArgumentParser(description="Apply P. Kocher's TA algorithm")
    argparser.add_argument("datafile", metavar='file', 
                        help='name of the data file (generated with ta_acquisition)')
    argparser.add_argument("n", metavar='n', type=int,
                        help='number of experiments to use')
    args = argparser.parse_args()

    if args.n < 1:                                      # If invalid number of experiments.
        sys.exit ("Invalid number of experiments: %d (shall be greater than 1)" % args.n)

    # Read encryption times and ciphertexts. n is the number of experiments to use.
    read_datafile (args.datafile, args.n)

    # *****************************************************************************
    # * Compute the Hamming weight of output of first (leftmost) SBox during last *
    # * round, under the assumption that the last round key is all zeros.         *
    # *****************************************************************************
    #rk = 0x000000000000
    # Undoes the final permutation on cipher text of n-th experiment.
    #r16l16 = des.ip (ct[args.n - 1])
    # Extract right half (strange naming as in the DES standard).
    #l16 = des.right_half (r16l16)
    # Compute output of SBoxes during last round of first experiment, assuming
    # the last round key is all zeros.
    #sbo = des.sboxes (des.e (l16) ^ rk)  # R15 = L16, K16 = rk
    # Compute and print Hamming weight of output of first SBox (mask the others).
    #print >> sys.stderr, "Hamming weight: %d" % hamming_weight (sbo & 0xf0000000)


    #rk = attack_Combine (args.n)
    rk = attack_Pearson (args.n)
    #rk = attack_Basic (args.n)
    # ************************************
    # * Compute and print average timing *
    # ************************************
    print >> sys.stderr, "Average timing: %f" % (sum (t) / args.n)

    # ************************
    # * Print last round key *
    # ************************

    print >> sys.stderr, "Last round key (hex):"
    print >> sys.stdout, ("0x%012X" % rk)

# Open datafile <name> and store its content in global variables
# <ct> and <t>.
def read_datafile (name, n):
    global ct, t

    if not isinstance (n, int) or n < 0:
        raise ValueError('Invalid maximum number of traces: ' + str(n))

    try:
        f = open (str(name), 'rb')
    except IOError:
        raise ValueError("cannot open file " + name)
    else:
        try:
            ct = []
            t = []
            for _ in xrange (n):
                a, b = f.readline ().split ()
                ct.append (int(a, 16))
                t.append (float(b))
        except (EnvironmentError, ValueError):
            raise ValueError("cannot read cipher text and/or timing measurement")
        finally:
            f.close ()

# ** Returns the Hamming weight of a 64 bits word.
# * Note: the input's width can be anything between 0 and 64, as long as the
# * unused bits are all zeroes.
# See: http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
def hamming_weight (v):
    v = v - ((v>>1) & 0x5555555555555555)
    v = (v & 0x3333333333333333) + ((v>>2) & 0x3333333333333333)
    return (((v + (v>>4) & 0xF0F0F0F0F0F0F0F) * 0x101010101010101) >> 56) & 0xFF

def attack_Basic (n):
	
	mask = 0x0000000f
	best_k16 = 0
	for s in range (8):
	   print "Sbox",s
	   score = []
           sco = 0.0
           best_sk = 0
	   for sk in range(64):
		#print "guess",sk
		fast = 0.0
		slow = 0.0
		n_fast = 0
		n_slow = 0
		for i in range (n):
			lr_16 = des.ip (ct[i])
			l_16 = des.right_half (lr_16)
			sbo = des.sboxes (des.e (l_16) ^ (sk << 6*s)) # ^ means xor
			hw = hamming_weight (sbo & (mask << 4*s)) # every time the sbo left shift 4 bits
			if hw == 0 or hw ==1: # hw = 0000 or 0000 0000 or ....depends on s
				fast += t[i]
				n_fast += 1
		
			if hw == 4 or hw == 3:# hw = 1111
				slow += t[i]
				n_slow += 1
		
		
		score.append (float (slow) / (n_slow) - float (fast) / (n_fast))

		if score[sk] > sco  :
			sco = score[sk]			
	   	 	best_sk=sk
			

	   best_k16 |= (best_sk << 6*s) 
	   print "best current key guess",("0x%012X" % best_k16)
	return (best_k16)
	
def attack_Pearson (n) :

	mask = 0x0000000f
	best_k16 = 0
	for s in range (8):
	   #print "Sbox",s
	   score = []
           sco = 0.0
           best_sk = 0
	   for sk in range(64):
		#print "guess",sk
		HW = []
		T = []
		#HW = numpy.array ([0 for x in xrange(n)])
		#T = numpy.array ([0 for x in xrange(n)])
		for i in range (n):
			lr_16 = des.ip (ct[i])
			l_16 = des.right_half (lr_16)
			sbo = des.sboxes (des.e (l_16) ^ (sk << 6*s)) # ^ means xor
			hw = hamming_weight (sbo & (mask << 4*s)) # every time the sbo left shift 4 bits
			#HW[i] = hw
			HW.append (hw)
			#T[i] = t[i]
			T.append (t[i])
			
		num = numpy.corrcoef(T,HW)
		#num = pcc(T,HW)
		#print num
		num = num[0][1]
		#print 'num', num
		score.append (num)
		#print score
		if score[sk] > sco  :
			sco = score[sk]			
	   	 	best_sk=sk
			

	   best_k16 |= (best_sk << 6*s) 
	   #print "best current key guess",("0x%012X" % best_k16)
	return (best_k16)

def attack_Combine (n) :

	mask = 0x0000000f
	best_k16 = 0
	for s in range (8):
	   print "Sbox",s
	   score_p = []
	   score = []
           sco = 0.0
           best_sk = 0
	   for sk in range(64):
		#print "guess",sk
		fast = 0.0
		slow = 0.0
		n_fast = 0
		n_slow = 0
		HW = []
		T = []
		for i in range (n):
			lr_16 = des.ip (ct[i])
			l_16 = des.right_half (lr_16)
			sbo = des.sboxes (des.e (l_16) ^ (sk << 6*s)) # ^ means xor
			hw = hamming_weight (sbo & (mask << 4*s)) # every time the sbo left shift 4 bits
			HW.append (hw)
			T.append (t[i])
			if hw == 0 or hw ==1: # hw = 0000 or 0000 0000 or ....depends on s
	
				fast += t[i]
				n_fast += 1
                                #print 'fast'
			if hw == 4 or hw ==3:# hw = 1111
			
				slow += t[i]
				n_slow += 1
				#print 'slow'
		
		score.append (float (slow) / (n_slow) - float (fast) / (n_fast))
		num = numpy.corrcoef(T,HW)
		#print num
		num = num[0][1]
		#print 'num', num
		score_p.append (num)
		#print score
		if score_p[sk] > 0 and score[sk]*score_p[sk]*score_p[sk] > sco  :
			sco = score[sk]*score_p[sk]*score_p[sk]			
	   	 	best_sk=sk
			

	   best_k16 |= (best_sk << 6*s) 
	   #print "best current key guess",("0x%012X" % best_k16)
	return (best_k16)

def pcc(X, Y):
   #Compute Pearson Correlation Coefficient. 
   # Normalise X and Y
   X -= X.mean(0)
   Y -= Y.mean(0)
   # Standardise X and Y
   X /= X.std(0)
   Y /= Y.std(0)
   # Compute mean product
   return numpy.mean(X*Y)			

if __name__ == "__main__":
    main ()
