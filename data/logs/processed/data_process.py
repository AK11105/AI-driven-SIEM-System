import csv
import glob
import json
import os, sys
from collections import defaultdict
import numpy as np
import re


datapath = 'tracebench/'
normal_trace_file = 'normal_trace.csv'
failure_trace_file = 'failure_trace.csv'
datafiles = glob.glob(datapath + '*/event.csv')
digit_pattern = r'[0-9][^a-z^/]*'

### Build event Id hashmap
eventIdDict = dict()
eventCount = 0
for datafile in datafiles:
	reader = csv.reader(open(datafile, 'r'), delimiter=',')
	next(reader, None)  # skip the headers
	for row in list(reader):
		description = re.sub(digit_pattern, '', row[8].lower())
		eventName = row[2] + '+' + description
		if eventName not in eventIdDict:
			eventIdDict[eventName] = eventCount
			eventCount += 1
print('Total events: ', eventCount)
sorted_eventIdDict = sorted(eventIdDict.items(), key=lambda x: x[1])
json.dump(sorted_eventIdDict, open('eventId.json', 'w'))


### Extract NM tasks
taskIdDict = dict()
taskCount = 0
normal_trace = defaultdict(list)
for datafile in datafiles:
	if 'NM_' in datafile:
		print(datafile)
		reader = csv.reader(open(datafile, 'r'), delimiter=',')
		next(reader, None)  # skip the headers
		for row in list(reader):
			taskName = row[0]
			if taskName not in taskIdDict:
				taskIdDict[taskName] = taskCount
				taskCount += 1
			description = re.sub(digit_pattern, '', row[8].lower())
			eventName = row[2] + '+' + description
			normal_trace[taskIdDict[taskName]].append(eventIdDict[eventName])
print('Total normal tasks: ', taskCount)
sorted_taskIdDict = sorted(taskIdDict.items(), key=lambda x: x[1])
json.dump(sorted_taskIdDict, open('normal_taskId.json', 'w'))

outputFile = open(normal_trace_file, 'w')
outputWriter = csv.writer(outputFile, lineterminator='\n')

outstream = ['TaskID']
for (eventName, eventId) in sorted_eventIdDict:
	outstream.append(eventName)
outputWriter.writerow(outstream)

for (taskName, taskId) in sorted_taskIdDict:
	event_counter_vector = np.zeros(eventCount)
	for eventId in normal_trace[taskId]:
		event_counter_vector[eventId] += 1
	outstream = event_counter_vector.tolist()
	outstream.insert(0, taskName) 
	outputWriter.writerow(outstream)
outputFile.close()


### Extract failure tasks
taskIdDict = dict()
failedTaskLabelDict = dict()
taskCount = 0
failure_trace = defaultdict(list)
for datafile in datafiles:
	if 'AN_' in datafile or 'COM_' in datafile:
		print(datafile)
		reader = csv.reader(open(datafile, 'r'), delimiter=',')
		next(reader, None)  # skip the headers
		for row in list(reader):
			taskName = row[0]
			if taskName not in taskIdDict:
				taskIdDict[taskName] = taskCount
				taskCount += 1
			description = re.sub(digit_pattern, '', row[8].lower())
			eventName = row[2] + '+' + description
			if 'success:' not in description and 'a user task' not in description:
				failedTaskLabelDict[taskName] = 'failure'
			failure_trace[taskIdDict[taskName]].append(eventIdDict[eventName])
print('Total failure tasks: ', len(failedTaskLabelDict))
sorted_taskIdDict = sorted(taskIdDict.items(), key=lambda x: x[1])
json.dump(sorted_taskIdDict, open('failure_taskId.json', 'w'))


outputFile = open(failure_trace_file, 'w')
outputWriter = csv.writer(outputFile, lineterminator='\n')

outstream = ['TaskID']
for (eventName, eventId) in sorted_eventIdDict:
	outstream.append(eventName)
outputWriter.writerow(outstream)

for (taskName, taskId) in sorted_taskIdDict:
	if taskName not in failedTaskLabelDict:
		continue
	event_counter_vector = np.zeros(eventCount)
	for eventId in failure_trace[taskId]:
		event_counter_vector[eventId] += 1
	outstream = event_counter_vector.tolist()
	outstream.insert(0, taskName) 
	outputWriter.writerow(outstream)
outputFile.close()




















