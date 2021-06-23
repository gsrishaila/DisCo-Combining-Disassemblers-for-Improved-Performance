#!/usr/bin/env python3
#implement neural network to give binary values
from google.colab import files
import numpy as np 
files.upload()
#import data
import tensorflow as tf
from tensorflow.keras.datasets import imdb
from tensorflow.keras.preprocessing import sequence
from tensorflow.python.keras.layers import Input, LSTM, Bidirectional, Dense, Embedding
#from colab
from numpy import loadtxt
from sklearn.metrics import confusion_matrix
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.model_selection import KFold
from sklearn.metrics import roc_auc_score
from sklearn.metrics import roc_curve
from matplotlib import pyplot
from numpy import argmax
from sklearn.metrics import precision_recall_curve
from numpy import arange
from sklearn.metrics import f1_score
#import tensorflow.compat.v1 as tf
#tf.disable_v2_behavior()
#ran this in separate cell pip install tensorflow==1.14
from numpy import loadtxt
from numpy import concatenate
from numpy import column_stack
from sklearn.metrics import confusion_matrix
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.model_selection import KFold
from sklearn.metrics import roc_auc_score
from sklearn.metrics import roc_curve
from matplotlib import pyplot
from numpy import argmax
from sklearn.metrics import precision_recall_curve
from numpy import delete
from numpy import concatenate
from tensorflow.keras.utils import to_categorical
from datasketch import MinHash, MinHashLSH
from nltk import ngrams


import re
import sys
import os

# apply threshold to positive probabilities to create labels
def to_labels(pos_probs, threshold):
	return (pos_probs >= threshold).astype('int')


def removeDataFoundByNoDisassembler(dataset_labels,dataset):
	rowListToDel=[]
	trueAddedByBN=0
	falseAddedByBN=0
	trueAddedByIda=0
	falseAddedByIda=0
	actualCorrect=0
	actualWrong=0
	print('dataset before removeDataFoundByNoDisassembler: %s' % str(dataset.shape))
	for i in range(0, dataset.shape[0]):
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0: #and dataset[i,5]==1: # last cond commented out
			rowListToDel.append(i)
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0 and dataset[i,5]==1 and dataset[i,6]==1:
			trueAddedByBN = trueAddedByBN +1
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0 and dataset[i,5]==1 and dataset[i,6]==0:
			falseAddedByBN = falseAddedByBN +1
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0 and dataset[i,5]==1 and dataset[i,6]==0:
			falseAddedByBN = falseAddedByBN +1
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==1 and dataset[i,6]==1:# and dataset[i,6]==1:
			trueAddedByIda = trueAddedByIda +1
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==1 and dataset[i,6]==0:# and dataset[i,6]==0:
			falseAddedByIda = falseAddedByIda +1
		if dataset[i,6]==1: 
			actualCorrect= actualCorrect+1
		if dataset[i,6]==0: 
			actualWrong= actualWrong+1
	dataset_labels = delete(dataset_labels,rowListToDel,0)
	dataset = delete(dataset,rowListToDel,0)
	print('dataset_labels: %s' % str(dataset_labels.shape))
	print('dataset after removeDataFoundByNoDisassembler: %s' % str(dataset.shape))
	print('trueAddedByBN: %s' % str(trueAddedByBN))
	print('falseAddedByBN: %s' % str(falseAddedByBN))
	print('trueAddedByBN: %s' % str(trueAddedByBN))
	print('falseAddedByBN: %s' % str(falseAddedByBN))
	print('trueAddedByIda: %s' % str(trueAddedByIda))
	print('falseAddedByIda: %s' % str(falseAddedByIda))
	print('actualCorrect: %s' % str(actualCorrect))
	print('actualWrong: %s' % str(actualWrong))
	return dataset_labels,dataset,len(rowListToDel)

def removeDuplicateLines(dataset_labels,dataset):
	#https://stackoverflow.com/questions/35873877/remove-duplicates-based-on-one-field-in-a-numpy-array
	#https://pythonhealthcare.org/2018/04/11/40-removing-duplicate-data-in-numpy-and-pandas/
	rows = dataset.shape[0]
	cols = dataset.shape[1]
	print('Shape of data (dataset.shape[0]): %s' % str(dataset.shape[0]))
	print('Shape of data (dataset.shape[1]): %s' % str(dataset.shape[1]))
	unique, index = np.unique(dataset, axis=0, return_index=True)
	print('Shape of data (unique): %s' % str(unique.shape))
	print('len(index): %s' % len(index))
	newdataset = dataset[np.sort(index)]
	print('newdataset shape: %s' % str(newdataset.shape))
	newdataset_labels = dataset_labels[np.sort(index)]
	print('newdataset_labels shape: %s' % str(newdataset_labels.shape))
	newDatasetWithLabels = column_stack((newdataset_labels,newdataset))
	print('newDatasetWithLabels  shape: %s' % str(newDatasetWithLabels .shape))
	print(newDatasetWithLabels[0:9,:])
	return newdataset_labels,newdataset


def getSigToAddInGhi91_2 (testName,ypred,y_test,dataset):
	each8BytesSig = set()
	missingFuncSig =set()
	additionalFuncSig = set()
	wildCardFuncSig = set() #contains the set of sig with wildcards
	rows = ypred.shape[0]
	cols = ypred.shape[1]
	s = open("sigToAdd.txt", "a")
	sigAddedCounter =0
	#s.write("Test: "+testName+"\n") 
	#s.write("MissingFuncSig:: "+ str(len(missingFuncSig))+"\n")
	for i in range(0, dataset.shape[0]):
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0: #and  dataset[i,5]==0:
			continue #noone found
		if ypred[i]==1 and dataset[i,2]==0:
			sigAddedCounter = sigAddedCounter + 1
		if ypred[i]==1 : #and y_test[i]==1:#we want output from ensemble #and dataset[i,1] ==0:#initial was 7... col 5 is gndtruth
			'''
			funcSig = hex(dataset[i,6]) + "  " +hex(dataset[i,7]) + "  " + hex(dataset[i,8])+ "  " + hex(dataset[i,9])+ "  " + hex(dataset[i,10]) +"  " + hex(dataset[i,11]) + "  " + hex(dataset[i,12])+ "  " + hex(dataset[i,13])+ "  " + hex(dataset[i,14]) +"  "+hex(dataset[i,15]) + "  " + hex(dataset[i,16])+ "  " + hex(dataset[i,17])+ "  " + hex(dataset[i,18]) + "  "+hex(dataset[i,19]) + " " + hex(dataset[i,20])+ " " + hex(dataset[i,21])
			'''
			funcSig = hex(dataset[i,15]) +"  "+hex(dataset[i,16]) + "  " + hex(dataset[i,17])+ "  " + hex(dataset[i,18])+ "  " + hex(dataset[i,19]) + "  "+hex(dataset[i,20]) + " " + hex(dataset[i,21])+ " " + hex(dataset[i,22])
			if funcSig not in  missingFuncSig:
				missingFuncSig.add(funcSig)	
				s.write("  <pattern>"+"\n") #<patternpairs totalbits="32" postbits="16">
				s.write("      <data>"+"0x{:02x}".format(dataset[i,15]) +"{:02x}".format(dataset[i,16]) + "{:02x}".format(dataset[i,17]) + "{:02x}".format(dataset[i,18])+ " " + "0x{:02x}".format(dataset[i,19])  + "{:02x}".format(dataset[i,20]) + "{:02x}".format(dataset[i,21]) + "{:02x}".format(dataset[i,22])+"</data>"+"\n")
				s.write("      <setcontext name=\"TMode\" value=\"0\"/>"+"\n")
				s.write("      <possiblefuncstart/>"+"\n")
				s.write("  </pattern>"+"\n")
				#adding sigs into set
				currSig = "{:02x}".format(dataset[i,15]) + "," + "{:02x}".format(dataset[i,16]) + "," +"{:02x}".format(dataset[i,17]) + "," + "{:02x}".format(dataset[i,18]) + "," + "{:02x}".format(dataset[i,19]) + "," + "{:02x}".format(dataset[i,20]) + "," +"{:02x}".format(dataset[i,21]) + "," + "{:02x}".format(dataset[i,22])
				each8BytesSig.add(currSig)
				#adding sigs into set
		if ypred[i]==0 and y_test[i]==0 and dataset[i,1] ==1:
			funcSig =hex(dataset[i,7]) + "  " + hex(dataset[i,8]) + "  " + hex(dataset[i,9])+ "  " + hex(dataset[i,10])+ "  " + hex(dataset[i,11]) + "  "+hex(dataset[i,12]) + "  " + hex(dataset[i,13])+ "  " + hex(dataset[i,14])+ "  " + hex(dataset[i,15]) +"  "+hex(dataset[i,16]) + "  " + hex(dataset[i,17])+ "  " + hex(dataset[i,18])+ "  " + hex(dataset[i,19]) +"  " +hex(dataset[i,20]) + "  " + hex(dataset[i,21])+ "  " + hex(dataset[i,22])
			additionalFuncSig.add(funcSig)
	s.close()
	f = open("sig.txt", "a")
	f.write("Test: "+testName+"\n") 
	f.write("MissingFuncSig:: "+ str(len(missingFuncSig))+"\n")
	#print('Test: %s\n' %testName)
	#print('Missing Sig::%d\n' %len(missingFuncSig))
	for x in missingFuncSig:
		#print (x)
		f.write(x+"\n")
		#print ("\n")
	f.write("Additional Sig:: "+ str(len(additionalFuncSig))+"\n")
	#print('Additional Sig::%d\n'%len(additionalFuncSig))
	for x in additionalFuncSig:
		#print (x + "\n")
		f.write(x+"\n")
		#print ("\n")
	f.close()
	#use minhashlsh to cluster similar strings
	#1. convert each8BytesSig set to list
	each8BytesSigList = list(each8BytesSig)

	lsh = MinHashLSH(threshold=0.65, num_perm=128)#0.7
	clusterDist = {}
	# Create MinHash objects
	minhashes = {}
	clusterIdx =0
	for c, i in enumerate(each8BytesSigList):
		minhash = MinHash(num_perm=128)
		for d in ngrams(i, 3):
			minhash.update("".join(d).encode('utf-8'))
		lsh.insert(c, minhash)
		minhashes[c] = minhash
	f = open("clusterSig.txt", "a")
	'''
	for i in range(len(minhashes.keys())):
		result = lsh.query(minhashes[i])
		#print ("Candidates with Jaccard similarity > 0.7 for input", i, ":", result)
		done=0
		for eachIdx in result:
			#print(each8BytesSigList[eachIdx])
			#f.write(str(eachIdx)+" : " +str(each8BytesSigList[eachIdx])+"\n") 
			#f.write(str(i)+"  :  " +str(result)+"\n")  #write in file i-one ele in cluster  result-cluster
			#print("\n")
			if eachIdx in clusterDist.keys(): #if one of the element in cluster is in dict,
				concatList = list()
				#concatList = list(set(clusterDist[eachIdx] + list(result)))
				concatList = list(clusterDist[eachIdx]) + list(result)
				concatList =list(set(concatList))
				clusterDist[eachIdx] = concatList
				done=1
				break
		if done ==0:
			clusterDist[i] = set(list(result))
	'''
	for i in range(len(minhashes.keys())):
		result = lsh.query(minhashes[i])
		done =0
		for eachClusterKey in clusterDist.keys():
			#find the intersection
			if len(set(result))>=10 :  #we dont want to keep adding clusters with just one sig
				intersectionSet = set(clusterDist[eachClusterKey]).intersection(set(result))
				percentageIntersection = (len(intersectionSet)/min(len(set(result)),len(set(clusterDist[eachClusterKey])))) * 100
				if percentageIntersection> 0.9:
					concatSet = set(clusterDist[eachClusterKey]).union(set(result))
					clusterDist[eachClusterKey] = list(concatSet)
					done=1	
		if done ==0:# we did not find any cluster to combile with
			clusterIdx = clusterIdx +1 
			clusterDist[clusterIdx] = list(set(result))
			done=1	
	#print each cluster
	for eachClusterIdx in clusterDist.keys():
		f.write(str(eachClusterIdx)+"  :  " +str(clusterDist[eachClusterIdx])+"\n") 	
		f.write("Size of Cluster::"+str(len(clusterDist[eachClusterIdx]))+"\n")
		clusterSize = len(clusterDist[eachClusterIdx])
		clusterSigPosDict = {}
		for eachEle in clusterDist[eachClusterIdx]:
			f.write(str(each8BytesSigList[eachEle])+"\n")	
			#remove , from each signature
			eachSig = each8BytesSigList[eachEle].replace(',', '')
			#f.write(eachSig+"\n")
			byteArray = list(eachSig)
			#byteArray = each8BytesSigList[eachEle].split(",")
			#f.write("len(byteArray)::"+str(len(byteArray))+"\n")
			#for eachByte in byteArray:
			for curIdx in range(len(byteArray)):
				#curIdx = byteArray.index(eachByte)
				#f.write("curIdx::"+str(curIdx)+" eachByte::"+str(byteArray[curIdx])+"\n")
				if curIdx in clusterSigPosDict.keys():
					clusterSigPosDict[curIdx].add(byteArray[curIdx])
				else:
					newSet = set()
					newSet.add(byteArray[curIdx])
					clusterSigPosDict[curIdx] = newSet
		#find positions to replace with wildcards
		wildCardSet = set()
		for eachPos in clusterSigPosDict.keys():
			#percentageVar = len(clusterSigPosDict[eachPos])/clusterSize
			percentageVar = len(clusterSigPosDict[eachPos])/16 #only 16 possible values for each spot
			f.write(str(clusterSigPosDict[eachPos])+"\n")
			f.write(str(len(clusterSigPosDict[eachPos]))+" / "+str(16)+" percentageVar::"+str(percentageVar)+"\n")
			if clusterSize>=10 and percentageVar>=0.40: #0.5
				wildCardSet.add(eachPos)
		f.write("percentageVar::"+str(percentageVar)+"\n")
		#create data content
		for eachEle in clusterDist[eachClusterIdx]:
			eachSig = each8BytesSigList[eachEle].replace(',', '')
			#f.write(eachSig+"\n")
			byteArray = list(eachSig)
			funcSigStr = ""
			for curIdx in range(len(byteArray)):
				if curIdx ==0 and curIdx in wildCardSet:
					funcSigStr = funcSigStr + "0x."
				elif curIdx ==0 and curIdx not in wildCardSet:
					funcSigStr = funcSigStr + "0x" + str(byteArray[curIdx]) 
				elif curIdx ==8 and curIdx  in wildCardSet:	
					funcSigStr = funcSigStr + " 0x."
				elif curIdx ==8 and curIdx not in wildCardSet:	
					funcSigStr = funcSigStr + " 0x" + str(byteArray[curIdx]) 
				elif curIdx  in wildCardSet:
					funcSigStr = funcSigStr + "."
				else:
					funcSigStr = funcSigStr + str(byteArray[curIdx]) 
			wildCardFuncSig.add(funcSigStr)
			f.write("funcSigStr::"+funcSigStr+"\n")						
		#for eachEle in clusterDist[eachClusterIdx]:	
		#	f.write(str(each8BytesSigList[eachEle])+"\n")
		#	byteArray = each8BytesSigList[eachEle].split(",")
		#	for i in range(len(byteArray)):
					
		#get size of set in each pos for each cluster
		#if set size is significant relative to cluster size ->replace this position with wildcard , save new sigs in set
		#create sig file based on this		
	f.close()
	#use minhashlsh to cluster similar strings
	f = open("SigWithWildcards.txt", "a")
	for eachWildCardSig in wildCardFuncSig:
		f.write("  <pattern>"+"\n") #<patternpairs totalbits="32" postbits="16">
		f.write("      <data>"+eachWildCardSig+"</data>"+"\n")
		f.write("      <setcontext name=\"TMode\" value=\"0\"/>"+"\n")
		f.write("      <possiblefuncstart/>"+"\n")
		f.write("  </pattern>"+"\n")
	f.close()
	print("sigAddedCounter::")
	print(sigAddedCounter)		
	return missingFuncSig, additionalFuncSig		
'''
#for arm we will tru just the postpattern
def getSigToAddInGhi91_2 (testName,ypred,y_test,dataset):
	missingFuncSig =set()
	additionalFuncSig = set()
	rows = ypred.shape[0]
	cols = ypred.shape[1]
	s = open("sigToAdd.txt", "a")
	s.write("Test: "+testName+"\n") 
	s.write("MissingFuncSig:: "+ str(len(missingFuncSig))+"\n")
	for i in range(0, dataset.shape[0]):
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0 and dataset[i,5]==0:
			continue #noone found
		if ypred[i]==1 and y_test[i]==1 and dataset[i,2] ==0:
			funcSig = hex(dataset[i,7]) + "  " +hex(dataset[i,8]) + "  " + hex(dataset[i,9])+ "  " + hex(dataset[i,10])+ "  " + hex(dataset[i,11]) +"  " + hex(dataset[i,12]) + "  " + hex(dataset[i,13])+ "  " + hex(dataset[i,14])+ "  " + hex(dataset[i,15]) +"  "+hex(dataset[i,16]) + "  " + hex(dataset[i,17])[2:]+ "  " + hex(dataset[i,18])+ "  " + hex(dataset[i,19]) + "  "+hex(dataset[i,20]) + " " + hex(dataset[i,21])+ " " + hex(dataset[i,22])
			missingFuncSig.add(funcSig)
		s.write("  <pattern>"+"\n") #<patternpairs totalbits="32" postbits="16">
		s.write("      <data>"+hex(dataset[i,15]) +hex(dataset[i,16])[2:] + hex(dataset[i,17])[2:] + hex(dataset[i,18])[2:]+ " " + hex(dataset[i,19])  + hex(dataset[i,20])[2:] + hex(dataset[i,21])[2:] + hex(dataset[i,22])[2:]+"</data>"+"\n")
		s.write("      <setcontext name=\"TMode\" value=\"0\"/>"+"\n")
		s.write("      <possiblefuncstart/>"+"\n")
		s.write("  </pattern>"+"\n")
		if ypred[i]==0 and y_test[i]==0 and dataset[i,2] ==1:
			funcSig =hex(dataset[i,7]) + "  " + hex(dataset[i,8]) + "  " + hex(dataset[i,9])+ "  " + hex(dataset[i,10])+ "  " + hex(dataset[i,11]) + "  "+hex(dataset[i,12]) + "  " + hex(dataset[i,13])+ "  " + hex(dataset[i,14])+ "  " + hex(dataset[i,15]) +"  "+hex(dataset[i,16]) + "  " + hex(dataset[i,17])+ "  " + hex(dataset[i,18])+ "  " + hex(dataset[i,19]) +"  " +hex(dataset[i,20]) + "  " + hex(dataset[i,21])+ "  " + hex(dataset[i,22])
			additionalFuncSig.add(funcSig)
	s.close()
	f = open("sig.txt", "a")
	f.write("Test: "+testName+"\n") 
	f.write("MissingFuncSig:: "+ str(len(missingFuncSig))+"\n")
	#print('Test: %s\n' %testName)
	#print('Missing Sig::%d\n' %len(missingFuncSig))
	for x in missingFuncSig:
		#print (x)
		f.write(x+"\n")
		#print ("\n")
	f.write("Additional Sig:: "+ str(len(additionalFuncSig))+"\n")
	#print('Additional Sig::%d\n'%len(additionalFuncSig))
	for x in additionalFuncSig:
		#print (x + "\n")
		f.write(x+"\n")
		#print ("\n")
	f.close()		
	return missingFuncSig, additionalFuncSig
'''


def getResultsForTest (testName,data_labels,dataset,y_pred,y_test):
	print ("getResultsForTest\n")
	tp=0
	tn=0
	fp=0
	fn=0
	testNoDisCnt=0
	label = ""
	curr_label = ""
	f = open("malware.txt", "a")
	f.write("Test: "+testName+"\n") 
	for i in range(0, data_labels.shape[0]):
		label = data_labels[i] 
		#print ("label111::" +label + "\n")
		progName = label.split("/")
		#print ("progName::" +progName[0] + "\n")
		if curr_label == "": 
			curr_label = progName[0]
		if curr_label !="" and  curr_label != progName[0]:
			#calculate precision, recall, f1
			precision   = (tp/(tp+fp))*100
			recall      = (tp/(tp+fn+testNoDisCnt))*100   #we add testNoDisCnt
			f1          = ((2*precision*recall)/(precision+recall))
			accuracy    = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
			sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
			fPR         = (fp/(fp + tn))*100              #False Positive Rate
			#update	curr_label
			f.write(str(curr_label)+"/,"+ str(precision) + "," + str(recall) +"," +str(f1)+"\n")
			curr_label  = progName[0]
			tp=0
			tn=0
			fp=0
			fn=0
			testNoDisCnt=0
		#check if nodis found it
		#if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0 and dataset[i,5]==0:
		if dataset[i,0]==0 and dataset[i,1]==0 and dataset[i,2]==0 and dataset[i,3]==0 and dataset[i,4]==0 and dataset[i,5]==0 and dataset[i,6]==1:
			testNoDisCnt = testNoDisCnt + 1	
			continue
		if y_pred[i] ==1 and y_test[i] ==1:
			tp = tp +1
		if y_pred[i] ==1 and y_test[i] ==0:
			fp = fp +1
		if y_pred[i] ==0 and y_test[i] ==1:
			fn = fn +1
		if y_pred[i] ==0 and y_test[i] ==0:
			tn = tn +1
	#get result for last program
	f.write(str(curr_label)+"/,"+ str(precision) + "," + str(recall) +"," +str(f1)+"\n")
	f.close()	
	

def main():	
	dataset           = loadtxt('armTrain_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	dataset_labels    = loadtxt('armTrain_All.csv',dtype='str',delimiter=',', usecols=0)
	print('Shape of data (dataset_labels): %s' % str(dataset_labels.shape))
	print('Shape of data (dataset): %s' % str(dataset.shape))
	datasetWithLabels = column_stack((dataset_labels,dataset))
	print('Shape of data (datasetWithLabels): %s' % str(datasetWithLabels.shape))
	print (datasetWithLabels[0]) 
	print (datasetWithLabels[0][0]) 
	print (datasetWithLabels[0][1]) 
	dataset_labels,dataset = removeDuplicateLines(dataset_labels,dataset)

	dataset_labels,dataset,noDisCnt =removeDataFoundByNoDisassembler(dataset_labels,dataset)
	
	#get Gnd Truth
	y = dataset[:, 6] #5 to 6
	X_foundByDis = dataset[:,0:5]  #5 to 6  #  change back to 5 ignore BN
	print('Shape of data (X_foundByDis): %s' % str(X_foundByDis.shape))
	'''
	print(dataset[0])
	print(X_foundByDis[0])
	print(dataset[1])
	print(X_foundByDis[1])
	print(dataset[2])
	print(X_foundByDis[2])
	print(dataset[3])
	print(X_foundByDis[3])
	print(dataset[4])
	print(X_foundByDis[4])
	print(y[0])
	print(y[1])
	print(y[2])
	print(y[3])
	print(y[4])
	'''

	X_toEncode =  dataset[:, 15:24]  #X_toEncode =  dataset[:, 6:23] #takes 16 cols  #X_toEncode =  dataset[:, 14:23] #takes 8 columns --14 to 15 23 to 24
	print('X_toEncode(BEFORE encode): %s' % str(X_toEncode.shape)) 
	print(X_toEncode[0])
	encoded = to_categorical(X_toEncode)
	print('encoded.shape: %s' % str(encoded.shape)) 
	encoded_reshaped =  encoded.reshape((X_foundByDis.shape[0],-1))  
	print('encoded_reshaped.shape: %s' % str(encoded_reshaped.shape)) 
	encodedX = concatenate((X_foundByDis,encoded_reshaped),axis=1)
	print('after concatenate encodedX.shape: %s' % str(encodedX.shape)) 
	X_train =  encodedX
	y_train =  y
	print('Shape of data X_train: %s' % str(X_train.shape))
	print('Shape of data y_train: %s' % str(y_train.shape))


	# create model 16 * 256 +5 =4096+5 =4101     #8*256 +5 = 2053
	''' #original
	model = Sequential()
	model.add(Dense(4101, input_dim=4101, activation='relu')) 
	model.add(Dense(1000, activation='relu')) #added in extra layer
	model.add(Dense(250, activation='relu')) #added in extra layer
	#model.add(Dense(60, activation='relu')) #added in extra layer
	model.add(Dense(1, activation='sigmoid'))
	'''
	model = Sequential()
	model.add(Dense(2053, input_dim=2053, activation='relu')) # 2053 to 2024  #change back from 2054 to 2053
	model.add(Dense(1000, activation='relu')) #added in extra layer
	model.add(Dense(250, activation='relu')) #added in extra layer
	#model.add(Dense(60, activation='relu')) #added in extra layer
	model.add(Dense(1, activation='sigmoid'))
	# Compile model
	model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

	n_split=10
	for traintrain_index,traintest_index in KFold(n_split).split(X_train):
	  x_traintrain,x_traintest=X_train[traintrain_index],X_train[traintest_index]
	  y_traintrain,y_traintest=y_train[traintrain_index],y_train[traintest_index]
	  model.fit(x_traintrain, y_traintrain,epochs=25,batch_size=200,verbose=0) #epoch used to be 75  batch size =40  #epochs=25,batch_size=100 3hrs 25,200 short 2,2000
	  model.evaluate(x_traintest,y_traintest)

	yhat = model.predict_proba(x_traintest)
	thresholds = arange(0, 1, 0.05)
	# evaluate each threshold
	scores = [f1_score(y_traintest, to_labels(yhat, t)) for t in thresholds]
	#getting best threshold by trying many thresholds
	# get best threshold
	ix = argmax(scores)
	print('Threshold=%.3f, F-Score=%.5f' % (thresholds[ix], scores[ix]))
	best_thresh = thresholds[ix]

	########GET SIGS##############################
	testNoDisCnt =0
	#get Test results
	#preparing testSet
	testGCCO0                  = loadtxt('armTrain_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testGCCO0_labels           = loadtxt('armTrain_All.csv',dtype='str',delimiter=',', usecols=0)
	testGCCO0_labels,testGCCO0,testNoDisCnt =removeDataFoundByNoDisassembler(testGCCO0_labels,testGCCO0)
	testy = testGCCO0[:, 6] 
	testX_foundByDis = testGCCO0[:,0:5]
	testX_toEncode   = testGCCO0[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("P2armTrain",testGCCO0_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armGCCO0.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armGCCO0.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	getSigToAddInGhi91_2 ("P2armTrain",y_pred,y_test,testGCCO0)
	########GET SIGS##############################
	
	
	testNoDisCnt =0
	#get Test results
	#preparing testSet
	testGCCO0                  = loadtxt('armGCCO0_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testGCCO0_labels           = loadtxt('armGCCO0_All.csv',dtype='str',delimiter=',', usecols=0)
	testGCCO0_labels,testGCCO0,testNoDisCnt =removeDataFoundByNoDisassembler(testGCCO0_labels,testGCCO0)
	testy = testGCCO0[:, 6] 
	testX_foundByDis = testGCCO0[:,0:5]
	testX_toEncode   = testGCCO0[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armGCCO0",testGCCO0_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armGCCO0.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armGCCO0.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armGCCO0",y_pred,y_test,testGCCO0)


	#GCCO1
	testGCCO1                  = loadtxt('armGCCO1_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testGCCO1_labels           = loadtxt('armGCCO1_All.csv',dtype='str',delimiter=',', usecols=0)
	testGCCO1_labels,testGCCO1,testNoDisCnt =removeDataFoundByNoDisassembler(testGCCO1_labels,testGCCO1)
	testy = testGCCO1[:, 6] 
	testX_foundByDis = testGCCO1[:,0:5]
	testX_toEncode   = testGCCO1[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armGCCO1",testGCCO1_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armGCCO1.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armGCCO1.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armGCCO1",y_pred,y_test,testGCCO1)

	#GCCO2
	testGCCO2                  = loadtxt('armGCCO2_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testGCCO2_labels           = loadtxt('armGCCO2_All.csv',dtype='str',delimiter=',', usecols=0)
	testGCCO2_labels,testGCCO2,testNoDisCnt =removeDataFoundByNoDisassembler(testGCCO2_labels,testGCCO2)
	testy = testGCCO2[:, 6] 
	testX_foundByDis = testGCCO2[:,0:5]
	testX_toEncode   = testGCCO2[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armGCCO2",testGCCO2_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armGCCO2.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armGCCO2.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armGCCO2",y_pred,y_test,testGCCO2)

	#GCCO3
	testGCCO3                  = loadtxt('armGCCO3_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testGCCO3_labels           = loadtxt('armGCCO3_All.csv',dtype='str',delimiter=',', usecols=0)
	testGCCO3_labels,testGCCO3,testNoDisCnt =removeDataFoundByNoDisassembler(testGCCO3_labels,testGCCO3)
	testy = testGCCO3[:, 6] 
	testX_foundByDis = testGCCO3[:,0:5]
	testX_toEncode   = testGCCO3[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armGCCO3",testGCCO3_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armGCCO3.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armGCCO3.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armGCCO3",y_pred,y_test,testGCCO3)

	#GCCOs
	testGCCOs                  = loadtxt('armGCCOs_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testGCCOs_labels           = loadtxt('armGCCOs_All.csv',dtype='str',delimiter=',', usecols=0)
	testGCCOs_labels,testGCCOs,testNoDisCnt =removeDataFoundByNoDisassembler(testGCCOs_labels,testGCCOs)
	testy = testGCCOs[:, 6] 
	testX_foundByDis = testGCCOs[:,0:5]
	testX_toEncode   = testGCCOs[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armGCCOs",testGCCOs_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armGCCOs.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armGCCOs.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armGCCOs",y_pred,y_test,testGCCOs)

	#Clang
	testClangO0                  = loadtxt('armClangO0_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testClangO0_labels           = loadtxt('armClangO0_All.csv',dtype='str',delimiter=',', usecols=0)
	testClangO0_labels,testClangO0,testNoDisCnt =removeDataFoundByNoDisassembler(testClangO0_labels,testClangO0)
	testy = testClangO0[:, 6] 
	testX_foundByDis = testClangO0[:,0:5]
	testX_toEncode   = testClangO0[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armClangO0",testClangO0_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armClangO0.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armClangO0.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armClangO0",y_pred,y_test,testClangO0)


	#ClangO1
	testClangO1                  = loadtxt('armClangO1_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testClangO1_labels           = loadtxt('armClangO1_All.csv',dtype='str',delimiter=',', usecols=0)
	testClangO1_labels,testClangO1,testNoDisCnt =removeDataFoundByNoDisassembler(testClangO1_labels,testClangO1)
	testy = testClangO1[:, 6] 
	testX_foundByDis = testClangO1[:,0:5]
	testX_toEncode   = testClangO1[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armClangO1",testClangO1_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armClangO1.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armClangO1.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armClangO1",y_pred,y_test,testClangO1)

	#ClangO2
	testClangO2                  = loadtxt('armClangO2_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testClangO2_labels           = loadtxt('armClangO2_All.csv',dtype='str',delimiter=',', usecols=0)
	testClangO2_labels,testClangO2,testNoDisCnt =removeDataFoundByNoDisassembler(testClangO2_labels,testClangO2)
	testy = testClangO2[:, 6] 
	testX_foundByDis = testClangO2[:,0:5]
	testX_toEncode   = testClangO2[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armClangO2",testClangO2_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armClangO2.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armClangO2.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armClangO2",y_pred,y_test,testClangO2)

	#ClangO3
	testClangO3                  = loadtxt('armClangO3_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testClangO3_labels           = loadtxt('armClangO3_All.csv',dtype='str',delimiter=',', usecols=0)
	testClangO3_labels,testClangO3,testNoDisCnt =removeDataFoundByNoDisassembler(testClangO3_labels,testClangO3)
	testy = testClangO3[:, 6] 
	testX_foundByDis = testClangO3[:,0:5]
	testX_toEncode   = testClangO3[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armClangO3",testClangO3_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armClangO3.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armClangO3.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armClangO3",y_pred,y_test,testClangO3)

	#ClangOs
	testClangOs                  = loadtxt('armClangOs_All.csv',dtype='int32',delimiter=',', usecols=range(1, 24), converters={_:lambda s: int(s, 16) for _ in range(1,24)})
	testClangOs_labels           = loadtxt('armClangOs_All.csv',dtype='str',delimiter=',', usecols=0)
	testClangOs_labels,testClangOs,testNoDisCnt =removeDataFoundByNoDisassembler(testClangOs_labels,testClangOs)
	testy = testClangOs[:, 6] 
	testX_foundByDis = testClangOs[:,0:5]
	testX_toEncode   = testClangOs[:,15:24]
	testencoded = to_categorical(testX_toEncode)
	testencoded_reshaped =  testencoded.reshape((testX_foundByDis.shape[0],-1))  
	testencodedX = concatenate((testX_foundByDis,testencoded_reshaped),axis=1)
	X_test =  testencodedX
	y_test =  testy
	print('Shape of data (X_test): %s' % str(X_test.shape))
	print('Shape of data (y_test): %s' % str(y_test.shape))
	#get all the zeros out
	y_pred = (model.predict(X_test)>=best_thresh)
	getResultsForTest ("armClangOs",testClangOs_labels,X_test,y_pred,y_test) #addedin
	tn, fp, fn, tp  = confusion_matrix(y_test, y_pred).ravel() 
	print('tp::',tp)
	print('tn::',tn)
	print('fp::',fp)
	print('fn::',fn)
	print('testNoDisCnt::',testNoDisCnt)
	precision = (tp/(tp+fp))*100
	recall    = (tp/(tp+fn+testNoDisCnt))*100 #we add testNoDisCnt
	f1        = ((2*precision*recall)/(precision+recall))
	accuracy  = ((tp+tn)/(tp+tn+fp+fn+testNoDisCnt))*100
	sensitivity = (tp/(tp+fn+testNoDisCnt))*100   #True  Positive Rate
	fPR = (fp/(fp + tn))*100         #False Positive Rate
	print('armClangOs.csv precision::'+str(precision) + "   recall     ::"+str(recall) + "   f1 ::"+str(f1) + "\n")
	print('armClangOs.csv accuracy ::'+str(accuracy) + "   sensitivity::"+str(sensitivity) + "   fPR::"+str(fPR) + "\n")
	
	#find signatures to add in Ghi91
	#getSigToAddInGhi91 ("armClangOs",y_pred,y_test,testClangOs)

	return 0

#find /home/shaila/Desktop/AllMainMalwareScripts_1/gcc/mips -type f -name '*O3_DisTruthfuncBytes.csv' -exec cat {} \; > mips03all.csv 
if __name__ == "__main__":
    sys.exit(main())



