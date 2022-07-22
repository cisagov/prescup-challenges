##############################################################################
##
##  API Extention to Measure time slept.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) bcrypt.lib
CFLAGS=$(CFLAGS) /EHsc

##############################################################################

all: dirs \
    $(BIND)\prescup$(DETOURS_BITS).dll \
    \
    option

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\prescup.obj : prescup.cpp

$(BIND)\prescup$(DETOURS_BITS).dll $(BIND)\prescup$(DETOURS_BITS).lib: \
        $(OBJD)\prescup.obj $(DEPS)
    cl /LD $(CFLAGS) /Fe$(@R).dll /Fd$(@R).pdb \
        $(OBJD)\prescup.obj \
        /link $(LINKFLAGS) /subsystem:console \
		/export:DetourFinishHelperProcess,@1,NONAME \
        $(LIBS)

##############################################################################

clean:
    -del *~ 2>nul
    -del $(BIND)\prescup*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\prescup$(DETOURS_OPTION_BITS).dll:
$(OPTD)\prescup$(DETOURS_OPTION_BITS).pdb:

$(BIND)\prescup$(DETOURS_OPTION_BITS).dll : $(OPTD)\prescup$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\prescup$(DETOURS_OPTION_BITS).pdb : $(OPTD)\prescup$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\prescup$(DETOURS_OPTION_BITS).dll \
    $(BIND)\prescup$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF
