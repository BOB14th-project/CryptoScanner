QT += widgets core
CONFIG += c++17 release silent object_parallel_to_source no_batch

TEMPLATE = app
TARGET = CryptoScanner

DEFINES += USE_MINIZ
DEFINES += QT_NO_DEBUG_OUTPUT QT_NO_WARNING_OUTPUT
DEFINES += MINIZ_NO_ZLIB_APIS MINIZ_NO_ARCHIVE_WRITING_APIS MZ_NO_MESSAGE

INCLUDEPATH += $$PWD
INCLUDEPATH += $$PWD/third_party/miniz
INCLUDEPATH += $$PWD/third_party/tree-sitter/lib/include
INCLUDEPATH += $$PWD/third_party/tree-sitter/lib/src

SOURCES += \
    gui_main_linux.cpp \
    CryptoScanner.cpp \
    FileScanner.cpp \
    PatternLoader.cpp \
    PatternDefinitions.cpp \
    JavaBytecodeScanner.cpp \
    JavaASTScanner.cpp \
    PythonASTScanner.cpp \
    CppASTScanner.cpp \
    DynLinkParser.cpp \
    third_party/miniz/miniz.c \
    third_party/miniz/miniz_zip.c \
    third_party/miniz/miniz_tinfl.c \
    third_party/tree-sitter/lib/src/lib.c \
    third_party/tree-sitter-cpp/src/parser.c \
    third_party/tree-sitter-cpp/src/scanner.c \
    third_party/tree-sitter-java/src/parser.c \
    third_party/tree-sitter-python/src/parser.c \
    third_party/tree-sitter-python/src/scanner.c

HEADERS += \
    CryptoScanner.h \
    FileScanner.h \
    PatternLoader.h \
    PatternDefinitions.h \
    JavaBytecodeScanner.h \
    JavaASTScanner.h \
    PythonASTScanner.h \
    CppASTScanner.h \
    ASTSymbol.h \
    DynLinkParser.h

QMAKE_CFLAGS   += -w -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -fPIC
QMAKE_CXXFLAGS += -w -fno-diagnostics-show-caret -fno-diagnostics-color -fno-diagnostics-show-option \
                  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -fPIC
QMAKE_CXXFLAGS += -Wno-unused-function -Wno-misleading-indentation

QMAKE_EXTRA_TARGETS += rebuild
rebuild.CONFIG  = phony
rebuild.target  = rebuild
rebuild.commands = $(MAKE) distclean; $$QMAKE_QMAKE $$PWD/CryptoScanner.pro; $(MAKE) -j$$system('nproc')

LIBS += -lssl -lcrypto
