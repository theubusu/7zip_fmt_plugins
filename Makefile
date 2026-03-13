OUTDIR=bin
INCLUDE=-lOleAut32 -lUser32 -Iinclude/7zip
DEFINE=-D_CRT_SECURE_NO_WARNINGS

ifeq ($(DEBUG),1)
DEFINE += -DDEBUG
endif

all: x64 x86

x64:
	clang src/*.cpp --target=x86_64-windows-msvc -shared $(INCLUDE) $(DEFINE) -o $(OUTDIR)/fmt7z-x64.dll

x86:
	clang src/*.cpp --target=i386-windows-msvc -shared $(INCLUDE) $(DEFINE) -o $(OUTDIR)/fmt7z-x86.dll