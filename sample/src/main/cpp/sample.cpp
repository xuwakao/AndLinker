#include <jni.h>
#include <string>

#include "adl.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_owttwo_andlinker_sample_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "ADL C++";
    adlopen("/system/bin/linker64", 0);
    return env->NewStringUTF(hello.c_str());
}
