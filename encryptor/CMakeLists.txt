# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.


add_library( # Sets the name of the library.
        Encryption

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        src/main/cpp/encryption.cpp )

#add_library( # Sets the name of the library.
#        anti_debugger
#
#        # Sets the library as a shared library.
#        SHARED
#
#        # Provides a relative path to your source file(s).
#        src/main/cpp/anti_debugger.cpp )




    add_library(libcrypto STATIC IMPORTED)
    add_library(libssl STATIC IMPORTED)
#    add_library(libcurl STATIC IMPORTED)

    set_target_properties(libcrypto
                          PROPERTIES
                          IMPORTED_LOCATION
                          ${CMAKE_SOURCE_DIR}/static/${ANDROID_ABI}/lib/libcrypto.a)

    set_target_properties(libssl
                        PROPERTIES
                        IMPORTED_LOCATION
                        ${CMAKE_SOURCE_DIR}/static/${ANDROID_ABI}/lib/libssl.a)

#  set_target_properties(libcurl
#                        PROPERTIES
#                        IMPORTED_LOCATION
#                        ${CMAKE_SOURCE_DIR}/static/${ANDROID_ABI}/lib/libcurl.a)



    include_directories(src/main/cpp/include)


# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                        Encryption
                       #network_socket
                       libssl
                       libcrypto
                       #libcurl
                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib}
                       )

#target_link_libraries( # Specifies the target library.
#                        anti_debugger
#                       #libcurl
#                       # Links the target library to the log library
#                       # included in the NDK.
#                       ${log-lib}
#                       )

if (${ANDROID_ABI} STREQUAL "x86")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-warn-shared-textrel")
endif ()