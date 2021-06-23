CCARM=arm-linux-gnueabi-gcc-5
CCMIPS=mipsel-linux-gnu-gcc-5
CFLAGS3=-O3 -g3
CFLAGSStatic=-static -O3 -g3
EXTRA_LIBS=
SRC = $(basename $(wildcard *.c))
BIN:=$(SRC)_O0

all: $(SRC)
	#$(MAKE) getGndTruth
$(SRC): %: %.c
	#$(CCARM) $(CFLAGS0) -o $(@)_arm00 $< 
	#$(CCARM) $(CFLAGS1) -o $(@)_arm01 $<
	#$(CCARM) $(CFLAGS2) -o $(@)_arm02 $<
	$(CCARM) $(CFLAGS3) -o $(@)_arm03 $<
	#$(CCARM) $(CFLAGSSize) -o $(@)_armSize $<
	$(CCARM) $(CFLAGSStatic) -o $(@)_armStatic $<
	#$(CCARM) $(CFLAGSStaticNLink) -o $(@)_armStaticNLink $<
	#$(CCARM) $(CFLAGSStripped) -o $(@)_armStrip $<
	#$(CCMIPS) $(CFLAGS0) -o $(@)_mips00 $<
	#$(CCMIPS) $(CFLAGS1) -o $(@)_mips01 $<
	#$(CCMIPS) $(CFLAGS2) -o $(@)_mips02 $<
	$(CCMIPS) $(CFLAGS3) -o $(@)_mips03 $<
	#$(CCMIPS) $(CFLAGSSize) -o $(@)_mipsSize $<
	$(CCMIPS) $(CFLAGSStatic) -o $(@)_mipsStatic $<
	#$(CCMIPS) $(CFLAGSStaticNLink) -o $(@)_mipsStaticNLink $<
	#$(CCMIPS) $(CFLAGSStripped) -o $(@)_mipsStrip $<
	#$(MAKE) getGndTruth

getGndTruth:
	$(eval SRCARM := $(basename $(wildcard *_arm*)))
	#echo $(SRC)
	#echo $(SRCARM)
	$(foreach eachBin, $(SRCARM), ./elfmap -iwORFE -e $(eachBin)>$(eachBin).truth.map;)
	$(eval SRCMIPS := $(basename $(wildcard *_mips*)))
	$(foreach eachBin, $(SRCMIPS), ./elfmap -iwORFE -e $(eachBin)>$(eachBin).truth.map;)
	#./elfmap -iwORFE -e P2P_1stclient_arm00


clean:
	rm -f $(BIN)


#SRC=$(wildcard *.c)
#SRC += $( basename$(wildcard *.c))


