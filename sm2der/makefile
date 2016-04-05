# makefile for sm2 der lib
# linux platform
# if android, please reference to Android.mk
# Author : Simon Pang of catt2009 / steven.psm@gmail.com 
# based on libtommath,many thax to TOM
# 2013-1-04



LIBNAME=libsm2der.a
OBJECTS=asn_codecs_prim.o  constr_SEQUENCE.o     NativeEnumerated.o   per_opentype.o \
asn_SEQUENCE_OF.o  constr_SEQUENCE_OF.o  NativeInteger.o      per_support.o \
asn_SET_OF.o       constr_SET_OF.o       NULL.o               SM2Cipher.o \
ber_decoder.o      constr_TYPE.o         ObjectIdentifier.o   SM2PrivateKey.o \
ber_tlv_length.o   OBJECT_IDENTIFIER.o  SM2PublicKey.o \
ber_tlv_tag.o      der_encoder.o         ObjID.o              SM2Signature.o \
BIT_STRING.o       EccPublicKey.o        OCTET_STRING.o       xer_decoder.o \
BOOLEAN.o          ECPrivateKey.o        Parameters.o         xer_encoder.o \
constraints.o      INTEGER.o             per_decoder.o        xer_support.o \
constr_CHOICE.o    libSm2der.o           per_encoder.o




CC=gcc
CPP=gcc

CFLAGS  =  -I./     -D_LINUX #-fpermissive#-D_DEBUG

all: $(LIBNAME)


$(LIBNAME):  $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS)
	ranlib $@

.cpp.o:
	$(CPP) $(CFLAGS) $< -o $@ -c
.c.o:
	$(CC) $(CFLAGS) $< -o $@ -c 

.PHONY:clean
clean:
	-rm $(LIBNAME) $(OBJECTS)
