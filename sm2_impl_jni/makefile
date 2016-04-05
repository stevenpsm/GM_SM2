#make test for linux
#simon pang - catt2009 @2012-8-19


## linux make instruction
## 1.copy dir :[sm2der\sm2_impl\libtommath-0.42.0\openssl-0.9.8o] to the host
## 2.compile them seperately
## 3.
##
##


TEST_TARGET=libsm2_impl_jni.so
TEST_OBJ=sm2der_jni.o  sm2_jni.o  utils.o
CC=g++
CPP=g++
#JNI_H_PATH=/cygdrive/C/JAVA/jdk1_6_AND_1_8/jdk1.6.0_37/include
#JNI_H_PATH2=/cygdrive/C/JAVA/jdk1_6_AND_1_8/jdk1.6.0_37/include/win32

##/home/simon/openssl-0.9.8o/libcrypto.a
CFLAGS=  ../sm2der/libsm2der.a  ../sm2_impl/libsm2.a  ../libtommath-0.42.0/libtommath.a    -I../sm2_impl -I.  -shared -D_LINUX -D__GNUC__

all: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJ)
	$(CPP) -o $@ $(TEST_OBJ) $(CFLAGS)

.cpp.o:
	$(CPP) $(CFLAGS) $< -o $@ -c
.c.o:
	$(CC) $(CFLAGS) $< -o $@ -c
 	
.PHONY:clean
clean:
	-rm $(TEST_TARGET) $(TEST_OBJ) 
	
	

