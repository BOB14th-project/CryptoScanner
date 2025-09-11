QT += widgets core
CONFIG += c++17 release silent

TEMPLATE = app
TARGET = CryptoScanner

DEFINES += USE_MINIZ
DEFINES += QT_NO_DEBUG_OUTPUT QT_NO_WARNING_OUTPUT

INCLUDEPATH += $$PWD $$PWD/third_party/miniz

SOURCES += \
    gui_main_linux.cpp \
    CryptoScanner.cpp \
    FileScanner.cpp \
    PatternLoader.cpp \
    JavaBytecodeScanner.cpp \
    JavaASTScanner.cpp \
    PythonASTScanner.cpp \
    CppASTScanner.cpp \
    third_party/miniz/miniz.c \
    third_party/miniz/miniz_tinfl.c \
    third_party/miniz/miniz_tdef.c \
    third_party/miniz/miniz_zip.c

HEADERS += \
    CryptoScanner.h \
    FileScanner.h \
    PatternLoader.h \
    JavaBytecodeScanner.h \
    JavaASTScanner.h \
    PythonASTScanner.h \
    CppASTScanner.h

QMAKE_CFLAGS   += -w -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
QMAKE_CXXFLAGS += -w -fno-diagnostics-show-caret -fno-diagnostics-color -fno-diagnostics-show-option \
                  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
QMAKE_CXXFLAGS += -Wno-unused-function -Wno-misleading-indentation

DEFINES += MZ_NO_MESSAGE

QMAKE_EXTRA_TARGETS += rebuild
rebuild.CONFIG  = phony
rebuild.target  = rebuild
rebuild.commands = $(MAKE) distclean; $$QMAKE_QMAKE $$PWD/CryptoScanner.pro; $(MAKE) -j$$system('nproc')

LIBS += -lssl -lcrypto