cmake_minimum_required(VERSION 3.5)

project(laba1 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        json/cridentials.json
        json/cridentials_encrypted.json
        json/cridentials_to_encrypt.json
        listitem.ui
        listitem.cpp
        listitem.h
        resource.qrc

)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(laba1
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET laba1 APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(laba1 SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(laba1
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(laba1 PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

include(FindOpenSSL) # средствами CMake автоматически найти установленную OpenSSL на данной машине, если это возможно
target_include_directories(
    laba1
    PRIVATE
    C:/QT/Tools/OpenSSLv3/Win_x64/include)
target_link_libraries(
    laba1 # к какой цели подключать
    PRIVATE # в каком режиме подключать
    C:/Qt/Tools/OpenSSLv3/Win_x64/lib/libcrypto.lib) # что именно подключать

set_target_properties(laba1 PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(laba1)
endif()
