### Usage #########
#   
#  Build with (all platforms same): 
#     mkdir build && cd build
#     cmake ..  
#     cmake --build .
#
#  Now run with: 
#     ./tt  (linux/macOS)
#     tt.exe (windows)
#
################


CMAKE_MINIMUM_REQUIRED(VERSION 2.8.1)
PROJECT(tt)

# Create a target that will be compiled to an executable
add_executable(tt
    src/main.c
    src/tt/tt_api.c
    src/tt/tt_util.c
    src/tt/tt_base64.c
)


# Tell it where to search for it's headers
target_include_directories(tt
    PRIVATE
        src/tt
        src/externals
)

# Find third party dependencies based on your system
# Will error out if it cannot find them
# Of note, additional code will be needed to find these on windows
find_package(OpenSSL REQUIRED)
target_link_libraries(tt PRIVATE OpenSSL::SSL OpenSSL::Crypto)

find_package(CURL REQUIRED)
target_link_libraries(tt PUBLIC ${CURL_LIBRARIES})

# Add system dependencies
# Again, needs some custom logic for windows support
target_link_libraries(tt m)
