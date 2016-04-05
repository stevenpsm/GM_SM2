# sm2 implimentation based upon libTomMath library and goldbar's sm3 project
#
# Author : Simon Pang of catt2009 / steven.psm@gmail.com 
# 2012-6-22
#
# Andoid make file for test

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

#if you wanna display debug info to trace the route of GM profile,just open it:
#LOCAL_CFLAGS += -D_DEBUG=1

src_files:= \
	base64.cpp sm2_libtom.cpp
       
LOCAL_MODULE    := sm2_test

LOCAL_SRC_FILES := $(src_files)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../sm2_impl/ \
                    $(LOCAL_PATH)

LOCAL_STATIC_LIBRARIES := sm2impl tommath
                    
include $(BUILD_EXECUTABLE)


