#!/usr/bin/env python
import re
import sys
import os
import math
from subprocess import call
import subprocess
'''
    For the given path, get the List of all files in the directory tree 
'''
def getListOfFiles(dirName):
    # create a list of file and sub directories 
    # names in the given directory 
    listOfFile = os.listdir(dirName)
    allFiles = list()
    onlyOFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
	# Create full path
	fullPath = os.path.join(dirName, entry)
	# If entry is a directory then get the list of files in this directory 
	if os.path.isdir(fullPath):
		allFiles = allFiles + getListOfFiles(fullPath)
	else:
		allFiles.append(fullPath)        
    return allFiles   


def getFuncBytes (bindir,fileNameLastPart):
    print "\nCSVFile::%s" %(elem)
    binaryName =""
    fileNameLastPartWithCSV = fileNameLastPart+".csv"
    binaryName = elem.replace(fileNameLastPartWithCSV,"")
    print "binaryName::%s" %(binaryName)
    subprocess.call(["./getBytesArdFunc","-d", elem ,"-e",binaryName])
    listOfFiles1 = getListOfFiles(bindir)
    for filename in listOfFiles1:
        if filename.endswith("_DisTruthfuncBytes.csv"):
            print "filename::%s" %(filename)
            fileNameLastPart1 = fileNameLastPart+"2"
            os.rename(filename, filename.replace("_DisTruthfuncBytes", fileNameLastPart1))


#Example Command
#opt -load SrcInfo/SrcInfo.so -srcinfo /home/shaila/Desktop/spec2017Install/benchspec/CPU/519.lbm_r/buildARM/build_base_mytest-m64.0000/lbm.ir
if __name__ == "__main__":
    '''
    #Arm GCC in passport
    progs = [["Apexv4/"   ,"ExecutionClient/"        ,"f34c5c27b/"      ,"fed_bait/"         ,"GreeksSource/",
                      "Hoho/"     , "Hybrid/"                ,"knight/"         ,"lizkebab_client_1/","oblivion/",
	              "okami/"    ,"P2P_client/"             ,"P2P_Demon_Demon/","P2P_hax/"          ,"P2P_shouldwork/",
                      "P2P_yard/" ,"Prometheus_PrometheusV4/","RealOwari/"      ,"remaiten/"         ,"Shinoa/"],
                     ["myAkiru/"  ,"myApollo-v1/"            ,"myAres/"         ,"myB/"              ,"myBashlite/",
                      "myChikaraMiraiSource/","myDarkrai/"   ,"myEros2.0/"      ,"myExtendo/"        ,"mygemini/",
	              "myHorizon/","myjoshov3/"              ,"myKanashiv3/"    ,"mykowaimirAivariant/","myKuria.d321c6/",
                      "myL33Tv4/" ,"mylightaidra/"           ,"mymainkwari/"    ,"mymirai/"          ,"myOasis/",
                      "myOnryo/"  ,"myosirismiraisource/"    ,"myriftbot2/"     ,"myRootSenpaiMirai/",
                      "mySaikin/",
                      "mySatan/"  ,"myShinto-V4/"            ,"mySoraModified/" ,"myStorm-Net-master/","myzbot/"],
                     ["1stclient.f56861/", "alright.668c15/" ,"AngelsRep.115acf/","anti.1b9dd4/"      ,"baby.ffe352/",
                      "backupcli.00572c/","bigbear.5c3f3a/"  ,"Capone_Client.08798f/","Cbot/"         ,"Cclient/",
                      "Cheatsedited.d59165/","Cherry.68e274/","cherrys.623db2/"  ,"Chippy1337.f1fbfc/","client.e8942f/",
                      "client3.203250/","client4.591de8/"    ,"client_.a1f733/"  ,"client_2.e3ca87/","client_4.3bd9c7/",
                      "client_6.0b1b2f/","client_7.ee5100/"  , "client_9.873478/","cliente.dd52cc/" ,"irc_dos_bot.3e9e49/",
                      "L7_client.a948af/","LinuxWare_Client.f30608/","parabot.484893/","privatebot.4a1f9f/","Razor.001df0/"],
                    ["mymiraiSythe/","mymiraiTokyo/","mymiraiunknown/","myTimeoutSec-L7-V1/","myTsunami v3/",
                     "myVaporwave/","myXovaTest/","myYakuzaMirai/"]]
  
    dirNamePart1   = ["/media/shaila/My Passport/UbuntuGCC/Part1/arm/","/media/shaila/My Passport/UbuntuGCC/Part2/arm/",
                     "/media/shaila/My Passport/UbuntuGCC/Part3TLMISC/arm/","/media/shaila/My Passport/UbuntuGCC/Part3/arm/"]
    '''
    #Clang Arm
    '''
    progs = [["Apexv4/"   ,"ExecutionClient/"        ,"f34c5c27b/"      ,"fed_bait/"         ,"GreeksSource/",
                       "Hoho/"     , "Hybrid/"                ,"knight/"         ,"lizkebab_client_1/","oblivion/",
	               "okami/"    ,"P2P_client/"             ,"P2P_Demon_Demon/","P2P_hax/"          ,"P2P_shouldwork/",
                       "P2P_yard/" ,"Prometheus_PrometheusV4/","RealOwari/"      ,"remaiten/"         ,"Shinoa/"],
                      ["myAkiru/"  ,"myApollo-v1/"            ,"myAres/"         ,"myB/"              ,"myBashlite/",
                       "myChikaraMiraiSource/","myDarkrai/"   ,"myEros2.0/"      ,"myExtendo/"        ,"mygemini/",
	               "myHorizon/","myjoshov3/"              ,"myKanashiv3/"    ,"mykowaimirAivariant/","myKuria.d321c6/",
                       "myL33Tv4/" ,"mylightaidra/"           ,"mymainkwari/"    ,"mymirai/"          ,"myOasis/",
                       "myOnryo/"  ,"myosirismiraisource/"    ,"myriftbot2/"     ,"myRootSenpaiMirai/","mySaikin.adbfc5/",
                       "mySatan/"  ,"myShinto-V4/"            ,"mySoraModified/" ,"myStorm-Net-master/","myzbot/"],
                      ["1stclient.f56861/", "alright.668c15/" ,"AngelsRep.115acf/","anti.1b9dd4/"      ,"baby.ffe352/",
                       "backupcli.00572c/","bigbear.5c3f3a/"  ,"Capone_Client.08798f/","Cbot/"         ,"Cclient/",
                       "Cheatsedited.d59165/","Cherry.68e274/","cherrys.623db2/"  ,"Chippy1337.f1fbfc/","client.e8942f/",
                       "client3.203250/","client4.591de8/"    ,"client_.a1f733/"  ,"client_2.e3ca87/","client_4.3bd9c7/",
                       "client_6.0b1b2f/","client_7.ee5100/"  , "client_9.873478/","cliente.dd52cc/" ,"irc_dos_bot.3e9e49/",
                       "L7_client.a948af/","LinuxWare_Client.f30608/","parabot.484893/","privatebot.4a1f9f/","Razor.001df0/"],
                      ["mymiraiSythe/","mymiraiTokyo/","mymiraiunknown/","myTimeout Sec - L7 - V1/"       ,"myTsunami v3/",
                       "myVaporwave/","myXovaTest/","myYakuzaMirai/"]]
  
    dirNamePart1   = ["/home/shaila/Desktop/AllMainMalwareScripts_1/clang/arm/",
                      "/home/shaila/Desktop/AllMainMalwareScripts_1/MalwaresP2/clang2/arm/",
                      "/home/shaila/Desktop/AllMainMalwareScripts_1/MalwaresP3/newVersion1/TLMISC/clang/arm/",
                      "/home/shaila/Desktop/AllMainMalwareScripts_1/MalwaresP3/newVersion1/clang/arm/"]
    '''
    '''
    #GCC Mips
    progs = [["Apexv4/"   ,"ExecutionClient/"        ,"f34c5c27b/"      ,"fed_bait/"         ,"GreeksSource/",
                      "Hoho/"     , "Hybrid/"                ,"knight/"         ,"lizkebab_client_1/","oblivion/",
	              "okami/"    ,"P2P_client/"             ,"P2P_Demon_Demon/","P2P_hax/"          ,"P2P_shouldwork/",
                      "P2P_yard/" ,"Prometheus_PrometheusV4/","RealOwari/"      ,"remaiten/"         ,"Shinoa/"],
                     ["myAkiru/"  ,"myApollo-v1/"            ,"myAres/"         ,"myB/"              ,"myBashlite/",
                      "myChikaraMiraiSource/","myDarkrai/"   ,"myEros2.0/"      ,"myExtendo/"        ,"mygemini/",
	              "myHorizon/","myjoshov3/"              ,"myKanashiv3/"    ,"mykowaimirAivariant/","myKuria.d321c6/",
                      "myL33Tv4/" ,"mylightaidra/"           ,"mymainkwari/"    ,"mymirai/"          ,"myOasis/",
                      "myOnryo/"  ,"myosirismiraisource/"    ,"myriftbot2/"     ,"myRootSenpaiMirai/",
                      "mySaikin/",
                      "mySatan/"  ,"myShinto-V4/"            ,"mySoraModified/" ,"myStorm-Net-master/","myzbot/"],
                     ["1stclient.f56861/", "alright.668c15/" ,"AngelsRep.115acf/","anti.1b9dd4/"      ,"baby.ffe352/",
                      "backupcli.00572c/","bigbear.5c3f3a/"  ,"Capone_Client.08798f/","Cbot/"         ,"Cclient/",
                      "Cheatsedited.d59165/","Cherry.68e274/","cherrys.623db2/"  ,"Chippy1337.f1fbfc/","client.e8942f/",
                      "client3.203250/","client4.591de8/"    ,"client_.a1f733/"  ,"client_2.e3ca87/","client_4.3bd9c7/",
                      "client_6.0b1b2f/","client_7.ee5100/"  , "client_9.873478/","cliente.dd52cc/" ,"irc_dos_bot.3e9e49/",
                      "L7_client.a948af/","LinuxWare_Client.f30608/","parabot.484893/","privatebot.4a1f9f/","Razor.001df0/"],
                    ["mymiraiSythe/","mymiraiTokyo/","mymiraiunknown/","myTimeoutSec-L7-V1/","myTsunamiv3/",
                     "myVaporwave/","myXovaTest/","myYakuzaMirai/"]]
  
    dirNamePart1   = ["/home/shaila/Desktop/AllMainMalwareScripts_1/gcc/mips/","/home/shaila/Desktop/AllMainMalwareScripts_1/MalwaresP2/gcc/mips/",
	"/home/shaila/Desktop/AllMainMalwareScripts_1/MalwaresP3/newVersion1/TLMISC/gcc/mips/", "/home/shaila/Desktop/AllMainMalwareScripts_1/MalwaresP3/newVersion1/gcc/mips/"]
    '''
    
    #Clang Mips
    progs = [["Apexv4/strip"   ,
		"ExecutionClient/strip"        ,"f34c5c27b/strip"      ,"fed_bait/strip"         ,"GreeksSource/strip",
                "Hoho/strip"     , "Hybrid/strip"                ,"knight/strip"         ,"lizkebab_client_1/strip","oblivion/strip",
	        "okami/strip"    ,"P2P_client/strip"             ,"P2P_Demon_Demon/strip","P2P_hax/strip"          ,"P2P_shouldwork/strip",
                "P2P_yard/strip" ,"Prometheus_PrometheusV4/strip","RealOwari/strip"      ,"remaiten/strip"         ,"Shinoa/strip"
		],
	      ["myAkiru/strip"  ,"myApollo-v1/strip"            ,"myAres/strip"         ,"myB/strip"              ,"myBashlite/strip",
               "myChikaraMiraiSource/strip","myDarkrai/strip"   ,"myEros2.0/strip"      ,"myExtendo/strip"        ,"mygemini/strip",
	       "myHorizon/strip","myjoshov3/strip"              ,"myKanashiv3/strip"    ,"mykowaimirAivariant/strip","myKuria.d321c6/strip",
               "myL33Tv4/strip" ,"mylightaidra/strip"           ,"mymainkwari/strip"    ,"mymirai/strip"          ,"myOasis/strip",
               "myOnryo/strip"  ,"myosirismiraisource/strip"    ,"myriftbot2/strip"     ,"myRootSenpaiMirai/strip","mySaikin/strip",
               "mySatan/strip"  ,"myShinto-V4/strip"            ,"mySoraModified/strip" ,"myStorm-Net-master/strip","myzbot/strip"],
              ["1stclient.f56861/strip", "alright.668c15/strip" ,"AngelsRep.115acf/strip","anti.1b9dd4/strip"      ,"baby.ffe352/strip",
               "backupcli.00572c/strip","bigbear.5c3f3a/strip"  ,"Capone_Client.08798f/strip","Cbot/strip"         ,"Cclient/strip",
               "Cheatsedited.d59165/strip","Cherry.68e274/strip","cherrys.623db2/strip"  ,"Chippy1337.f1fbfc/strip","client.e8942f/strip",
               "client3.203250/strip","client4.591de8/strip"    ,"client_.a1f733/strip"  ,"client_2.e3ca87/strip","client_4.3bd9c7/strip",
               "client_6.0b1b2f/strip","client_7.ee5100/strip"  , "client_9.873478/strip","cliente.dd52cc/strip" ,"irc_dos_bot.3e9e49/strip",
               "L7_client.a948af/strip","LinuxWare_Client.f30608/strip","parabot.484893/strip","privatebot.4a1f9f/strip","Razor.001df0/strip"],
              ["mymiraiSythe/strip","mymiraiTokyo/strip","mymiraiunknown/strip","myTimeoutSec-L7-V1/strip" ,"myTsunamiv3/strip",
               "myVaporwave/strip","myXovaTest/strip",
               "myYakuzaMirai/strip"]
	]
  
    dirNamePart1   = [#"/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Mips/Part1/" #,
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Arm/Part1/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Arm/Part1/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Mips/Part1/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Mips/Part1/",
                      

		      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Arm/Part2/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Arm/Part2/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Mips/Part2/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Mips/Part2/",


                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Arm/Part3TLMISC/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Arm/Part3TLMISC/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Mips/Part3TLMISC/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Mips/Part3TLMISC/",



                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Arm/Part3/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Arm/Part3/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/Clang/Mips/Part3/",
                      "/media/shaila/My Passport/Sept25_CreateStripBins_updatedClangInst3/GCC/Mips/Part3/"]
                       
                      #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Mips/Part1/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Arm/Part1/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Mips/Part1/",
		  #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Arm/Part2/",
                     #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Mips/Part2/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Arm/Part2/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Mips/Part2/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Arm/Part3TLMISC/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Mips/Part3TLMISC/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Arm/Part3TLMISC/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Mips/Part3TLMISC/",
		  #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Arm/Part3/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Mips/Part3/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Arm/Part3/",
                  #"/media/shaila/My Passport/Sept25_CreateStripBins/Clang/Mips/Part3/"
		#]

    for eachdirNamePart1 in dirNamePart1: #for arm binaries change _MipsDissCSV.csv -> _ArmDissCSV.csv
        dirNamePart1Index =dirNamePart1.index(eachdirNamePart1)
        dirNamePart1Index = int(math.floor(dirNamePart1Index/4))
        for eachProg in progs[dirNamePart1Index]: 
            dirOfBinsdir = eachdirNamePart1 + eachProg
            listOfFiles = getListOfFiles(dirOfBinsdir)
            currDir =os.getcwd()+ '/'
            #create the LLVMInfo file
            for elem in listOfFiles:
                #if not ".txt" in elem and not ".info" in elem and not ".asmplus" in elem and not ".i64" in elem and not ".asm" in elem and ("_O0" in elem or "_O0" in elem) and "_ArmDissCSV.csv" in elem:
                #if not ".txt" in elem and not ".info" in elem and not ".asmplus" in elem and not ".i64" in elem and not ".asm" in elem and ("_MipsDissCSV.csv" in elem or "_ArmDissCSV.csv" in elem):
                 if not ".txt" in elem and not ".info" in elem and not ".asmplus" in elem and not ".i64" in elem and not ".asm" in elem: 
                     if "_ArmDissCSVClang_Ang_Ghi_Bap_Radare.csv" in elem: #Arm Clang
                         getFuncBytes (dirOfBinsdir,"_ArmDissCSVClang_Ang_Ghi_Bap_Radare")
                     if "_ArmDissCSVClang_Ida_Ghi.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_ArmDissCSVClang_Ida_Ghi")
                     if "_ArmDissCSVClang_All.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_ArmDissCSVClang_All")
                     if "_ArmDissCSVGCC_Ang_Ghi_Bap_Radare.csv" in elem: #Arm GCC
                         getFuncBytes (dirOfBinsdir,"_ArmDissCSVGCC_Ang_Ghi_Bap_Radare")
                     if "_ArmDissCSVGCC_Ida_Ghi.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_ArmDissCSVGCC_Ida_Ghi")
                     if "_ArmDissCSVGCC_All.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_ArmDissCSVGCC_All")
                     if "_MipsDissCSVClang_Ang_Ghi_Bap_Radare.csv" in elem: #Mips Clang
                         getFuncBytes (dirOfBinsdir,"_MipsDissCSVClang_Ang_Ghi_Bap_Radare")
                     if "_MipsDissCSVClang_Ida_Ghi.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_MipsDissCSVClang_Ida_Ghi")
                     if "_MipsDissCSVClang_All.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_MipsDissCSVClang_All")
                     if "_MipsDissCSVGCC_Ang_Ghi_Bap_Radare.csv" in elem: #Mips GCC
                         getFuncBytes (dirOfBinsdir,"_MipsDissCSVGCC_Ang_Ghi_Bap_Radare")
                     if "_MipsDissCSVGCC_Ida_Ghidra.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_MipsDissCSVGCC_Ida_Ghidra")
                     if "_MipsDissCSVGCC_All.csv" in elem:
                         getFuncBytes (dirOfBinsdir,"_MipsDissCSVGCC_All")
                         '''
                         print "\nCSVFile::%s" %(elem)
                         binaryName =""
                         binaryName = elem.replace("_ArmDissCSVClang_Ang_Ghi_Bap_Radare.csv","")
                         print "binaryName::%s" %(binaryName)
                         subprocess.call(["./getBytesArdFunc","-d", elem ,"-e",binaryName])
                         #change filename
                         listOfFiles1 = getListOfFiles(dirOfBinsdir)
                         for filename in listOfFiles1:
                             if filename.endswith("_DisTruthfuncBytes.csv"):
                                 print "filename::%s" %(filename)
                                 os.rename(filename, filename.replace("_DisTruthfuncBytes", "_ArmDissCSVClang_Ang_Ghi_Bap_Radare2"))
                         '''
                     #if "_ArmDissCSVClang_Ida_Ghi.csv" in elem:


#shaila@lassen:/media/shaila/My Passport/UbuntuGCC/Part1/arm$ find /media/shaila/My\ Passport/UbuntuGCC/Part1/arm  -type f -name '*Os_DisTruthfuncBytes.csv' -exec cat {} \; > armGccP1_Os.csv

#shaila@lassen:/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Arm/Part1$ find /media/shaila/My\ Passport/Sept25_CreateStripBins/GCC/Arm/Part1  -type f -name '*O0_DisTruthfuncBytes.csv' -exec cat {} \; > armGCCO0P1.csv

#shaila@lassen:/media/shaila/My Passport/Sept25_CreateStripBins/GCC/Arm/Part1$ find /media/shaila/My\ Passport/Sept25_CreateStripBins/GCC/Arm/Part1  -type f -name '*Os_DisTruthfuncBytes.csv' -exec cat {} \; > armGCCOsP1.csv


