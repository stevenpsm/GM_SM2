# sm2 implimentation based upon libTomMath library and goldbar's sm3 project
#
# Author : Simon Pang of catt2009 / steven.psm@gmail.com 
# 2012-6-22
#
# Andoid make file

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

#if you wanna display debug info to trace the route of GM profile,just open it:
#LOCAL_CFLAGS += -D_LINUX

src_files:= \
	sm2.cpp sm3.c sm2_Intrfs_test.cpp
       
LOCAL_MODULE    := sm2impl

LOCAL_SRC_FILES := $(src_files)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)

LOCAL_STATIC_LIBRARIES := tommath
                    
include $(BUILD_STATIC_LIBRARY)


