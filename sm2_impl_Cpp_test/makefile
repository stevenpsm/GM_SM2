#make test for linux
#simon pang - catt2009 @2012-6-26
TEST_TARGET=test_out_bin
TEST_OBJ=base64.o sm2_libtom.o
CC=g++
CPP=g++

CFLAGS=  ../sm2_impl/libsm2.a  ../libtommath-0.42.0/libtommath.a  -g -I../sm2_impl/ -I.  -D_LINUX  

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
	
	

