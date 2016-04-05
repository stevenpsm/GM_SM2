# makefile for sm2 lib
# linux platform
# if android, please reference to Android.mk
# Author : Simon Pang of catt2009 / steven.psm@gmail.com 
# 2012-6-22



LIBNAME=libsm2.a
OBJECTS=sm2.o sm3.o sm2_Intrfs_test.o
CC=g++
CPP=g++

CFLAGS  =  -I./   -g #-D_DEBUG

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
