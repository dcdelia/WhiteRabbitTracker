from collections import defaultdict
from intervalTree import *
from os import listdir
from os.path import isdir, isfile, join
import sys
import logging

genLogOffset = 2 # 0 for early versions, 2 for recent ones where we have timestamps

def parseMemLogHeader(splittedLine):
	# - NtQueryAttributesFile 0x76fc46c4 0x001a781c 0x001a7844
	name = splittedLine[1]
	ctxt = int(splittedLine[2], 16)
	hook_id = (name, ctxt) # name, ctxt hash
	start = int(splittedLine[3], 16)
	end = int(splittedLine[4], 16)
	memoryRange = (start, end) # get: start, end
	return hook_id, memoryRange


def parseMemLogBuffer(splittedLine):
	# 0x001a7820 0x001a7824 [1]
	start = int(splittedLine[0], 16)
	end = int(splittedLine[1], 16)
	# color apparently unused - TODO DROP IT?
	memoryRange = (start, end)
	return memoryRange

	
def getInstructionTypeForGeneralLog(splittedLine):
	idx = genLogOffset
	return splittedLine[idx+0].replace(";", "")


def parseGeneralLogForMemoryEntry(instructionType, splittedLine):
	# Original syntax
	# mem; 0x001454cb [1] push 0x004a70e0(4) NA 1 0x74a0519
	# mem-imm; 0x0014460d [1] cmp 0x004a75bc(4) 0 1 0x74b4e0e0
	# mem-reg; 0x0135c62f [2] mov 0x001af9c4(4) eax 2 0x745df585
	# reg-mem; 0x0013c701 [1] mov eax 0x004afa34(4) 2 0x74b3f585
	# When updating WhiteRabbitTracker we added heading timestamps here:
	# 651c 7095d2 reg-reg; 0x00769afc [2] bt dx di 1 0x7524e3ea
	idx = genLogOffset
	offsetForAddress = (idx+5) if instructionType == "reg-mem" else (idx+4)
	# extract fields
	ipAddress = int(splittedLine[idx+1], 16)
	taintColor = int(splittedLine[idx+2].replace("[", "").replace("]", ""))
	opcode = splittedLine[idx+3]
	memAddress = int(splittedLine[offsetForAddress].split("(")[0], 16)
	memSize = int(splittedLine[offsetForAddress].split("(")[1].replace(")", ""))
	assertType = int(splittedLine[idx+6])
	ctxt = int(splittedLine[idx+7], 16)
	return ipAddress, taintColor, opcode, memAddress, memSize, assertType, ctxt


def getDictConsumers(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	consumers = defaultdict(list)
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				for line in f:
					splittedLine = line.strip().split(" ")
					# consider only taint logs that involves memory areas
					memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
					instructionType = getInstructionTypeForGeneralLog(splittedLine)
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						# BEWARE it is not keeping track of the size here
						ipAddress, taintColor, opcode, memAddress, memSize, assertType, ctxt = parseGeneralLogForMemoryEntry(instructionType, splittedLine)	
						consumers[ipAddress].append(memAddress)
	return consumers


def generateAwfulOrder(start, end, vec):
	if start > end:
		return
	n, mod = divmod(end-start, 2)
	n = n + start
	vec.append(n)
	generateAwfulOrder(start, n-1, vec)
	generateAwfulOrder(n+1, end, vec)


def populateTaintedChunks(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	hook_id: (str, int) = None
	root: TaintedChunk = None
	prodLargeRange = {}  # dict(hook_id, memoryRange)
	prodMap = defaultdict(set)  # dict(hook_id, list<memoryRange>)

	for logFile in logFiles:
		# consider only memory areas logs
		if "mem" in logFile:
			print(f"Logfile: {logFile}")
			with open(directoryTaintedLogs + logFile) as f:
				for line in f:
					splittedLog = line.strip().split(" ")
					if splittedLog[0] == "-": # not really neat :)
						hook_id, memoryRange = parseMemLogHeader(splittedLog)
						prodLargeRange[hook_id] = memoryRange
					else:
						memoryRange = parseMemLogBuffer(splittedLog)
						# General strategy: avoid duplicates
						prodMap[hook_id].add(memoryRange)

	# we need this cheap trick until we use a self-balancing interval tree						
	sortedScz = []
	for prod in prodMap:
		for range in prodMap[prod]:
			pair = (range, prod)
			sortedScz.append(pair)
	print(f"Number of recorded memory chunks: {len(sortedScz)}")
	# first by decreasing range width, then by increasing start element. Still misses something though :/
	sortedScz.sort(key=lambda k: (-(k[0][1]-k[0][0]), k[0][0]))
	insertionOrder = []
	generateAwfulOrder(0, len(sortedScz)-1, insertionOrder)
	
	for idx in insertionOrder:
		range, prod = sortedScz[idx]
		start, end = range[0], range[1]
		if root is None:
			root = TaintedChunk(start, end, prod[1], 1, prod[0])
		else:
			node = overlapSearch(root, start, end)
			if node is None:
				insertTaintedChunk(root, start, end, prod[1], 1, prod[0])
			else:
				if (node.start <= start < node.end) and (node.start <= end <= node.end):
					pass # OK CASE
				elif start == node.end or node.start == end: # adjacent intervals
					insertTaintedChunk(root, start, end, prod[1], 1, prod[0])
				else:
					print(f"SKIPPING AN OVERLAPPING NODE! See {start:x}, {end:x} vs. {node.start:x}, {node.end:x}")

	return root, prodLargeRange


def populateDefinitiveChunks(definitiveChunks):
	root: TaintedChunk = None

	sortedScz = []
	for l in definitiveChunks.values():
		for range in l:
			sortedScz.append(range)
	sortedScz.sort(key=lambda k: (k[0]))
	insertionOrder = []
	generateAwfulOrder(0, len(sortedScz)-1, insertionOrder)

	for idx in insertionOrder:
		range = sortedScz[idx]
		start, end = range[0], range[1]
		if root is None:
			root = TaintedChunk(start, end, 0x0, 1, "f_technique")
		else:
			insertTaintedChunk(root, start, end, 0x0, 1, "f_technique")

	return root


def fTechnique(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	insCounterDict = defaultdict(int)  # dict<ipAddr: int, size: int> (hit counter)
	byteInsDict = defaultdict(set)  # dict<memAddr: int, list<int>> (set of instruction that accessed that byte)
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				for line in f:
					splittedLine = line.strip().split(" ")
					instructionType = getInstructionTypeForGeneralLog(splittedLine)
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						# TODO swap ifs for efficiency
						ipAddress, taintColor, opcode, memAddress, memSize, assertType, ctxt = parseGeneralLogForMemoryEntry(instructionType, splittedLine)
						# for "mem", "mem-imm" and "mem-reg" the memory operand is the first
						if instructionType == "mem" or instructionType == "mem-imm" or instructionType == "mem-reg":
							if assertType != 2:
								insCounterDict[ipAddress] += 1
								for i in range(0, memSize):
									byteInsDict[memAddress+i].add(ipAddress)
						# for "reg-mem" the memory operand is the second
						elif assertType != 1:
							insCounterDict[ipAddress] += 1
							for i in range(0, memSize):
								byteInsDict[memAddress+i].add(ipAddress)
	print(f"Size of byteInsDict for fTechnique: {len(byteInsDict)}")
	
	# Now calculate "preliminary" chunks
	preliminaryChunks = defaultdict(set)  # dict<int, list<int>> but we do not want duplicates
	# for all bytes in the map
	for bytesIns in byteInsDict.keys():
		# (ordered) list of instructions that accessed that byte
		listOfIns = list(byteInsDict[bytesIns])
		listOfIns.sort() # TODO sorting for breaking ties? unneeded?
		
		# look for lowest hitcount for all instructions in the bytes-set
		# TODO this was not implemented the way I suggested...
		hitCount = sys.maxsize
		ins = None
		for currentIns in listOfIns: # ins will be picked here
			insCount = insCounterDict[currentIns]
			if insCount < hitCount:
				hitCount = insCount
				ins = currentIns
		# add/update instruction in preliminary map
		preliminaryChunks[ins].add(bytesIns)
	
	# from preliminary chunks to final chunks
	definitiveChunks = defaultdict(set)  # dict<int, list<(chunkStart: int, chunkEnd: int)>
	for ins in preliminaryChunks.keys():
		l = list(preliminaryChunks[ins])
		l.sort() # sort bytes associated to instruction
		# merge adjacent addresses into a single chunk (previous code missed merges!)
		max = len(l)
		i = 0
		while i < max:
			j = i + 1
			while j < max and l[j] == (l[j-1] + 1):
				j = j + 1
			chunk = (l[i], l[j-1]+1) # TODO IMPORTANT: check later in uses whether end is included or not...
			i = j # to build next chunk (if any)
			definitiveChunks[ins].add(chunk)

	totalChunks = 0
	for s in definitiveChunks.items():
		for chunk in s:
			totalChunks = totalChunks + len(s)

	print(f"Definitive chunks from fTechnique: {totalChunks}")
	return definitiveChunks


def addrColourToChunksRoot(definitiveChunksRoot, addrCols):
	res: TaintedChunk = None

	for address, col in addrCols.items():
		res = searchTaintedChunk(definitiveChunksRoot, address)
		if res is not None:
			res.colour = col


# TODO check dictionary usage here
def findProdHeuristics(directoryTaintedLogs, definitiveChunksRoot):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	rangeProd = {}  # dict<pair<startMem: int, endMem: int>, pair<insAddress: int, color: int>>
	addrCol = {}  # dict<address: int, color: int>
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				for line in f:
					splittedLine = line.strip().split(" ")
					instructionType = getInstructionTypeForGeneralLog(splittedLine)
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						ipAddress, taintColor, opcode, memAddress, memSize, assertType, ctxt = parseGeneralLogForMemoryEntry(instructionType, splittedLine)
						# process memAddress
						if memAddress not in addrCol.keys():
							addrCol.update({memAddress: taintColor})
						else:
							addrCol[memAddress] = taintColor
						# if the memory is the destination operand -> it will be overwritten (expect for cmp and test)
						if opcode != "cmp" and opcode != "test" and opcode != "push" and \
								(instructionType == "mem-imm" or instructionType == "mem-reg"):
							res: TaintedChunk = searchTaintedChunk(definitiveChunksRoot, memAddress)
							if res is not None:
								if (res.start, res.end) not in rangeProd.keys():
									rangeProd.update({(res.start, res.end): (ctxt, taintColor)})
								else:
									rangeProd[(res.start, res.end)] = (ctxt, taintColor)
	return rangeProd, addrCol


def main():
	# sanity check
	if len(sys.argv) != 3:
		print("Usage: python offlineAnalysis.py PATH_TO_TAINTED_LOGS PATH_TO_CALL_STACK_LOG (e.g. offlineAnalysis.py C:\\Pin315\\taint\\ C:\\Pin315\\callstack.log)")
		return -1

	directoryTaintedLogs = sys.argv[1]
	callStackLog = sys.argv[2]

	# sanity checks
	if isdir(directoryTaintedLogs) is False:
		print("The given path to the tainted logs is not a directory!")
	if isfile(callStackLog) is False:
		print("The given path to the call stack log is not a file!")

	# create logging file
	for handler in logging.root.handlers[:]:
		logging.root.removeHandler(handler)
	try:
		f = open("graph.gv", "w")
	except IOError:
		print("File graph.gv not present, creating the file...")
	finally:
		f.close()

	logging.basicConfig(filename="graph.gv", format='%(message)s', level=logging.INFO)

	'''
	Create a dictionary where the:
		- keys: list of all consumers
		- value: list of addresses consumed by these consumers
	'''
	consumers = getDictConsumers(directoryTaintedLogs)
	print(f"Number of consumers found: {len(consumers)}")

	'''
	Create an interval tree that contains the tainted memory areas during the program execution
	'''
	taintProducerRoot, prodLargeRange = populateTaintedChunks(directoryTaintedLogs)

	definitiveChunks = fTechnique(directoryTaintedLogs)
	'''
	# DEBUG CHUNKS
	for chunk in definitiveChunks.keys():
		print(hex(chunk))
		for currentRange in definitiveChunks[chunk]:
			print("            ", hex(currentRange[0]), ",", hex(currentRange[1]))
	'''

	'''
	Create an interval tree that contains the definitive tainted chunks
	'''
	definitiveChunksRoot = populateDefinitiveChunks(definitiveChunks)

	'''
	Producer identification
	'''
	rangeProd, addrCol = findProdHeuristics(directoryTaintedLogs, definitiveChunksRoot)

	'''
	Add colors to interval tree
	'''
	addrColourToChunksRoot(definitiveChunksRoot, addrCol)

	'''
	It's time to build the .dot file (graph)
	'''
	consumerChunks = {} # dict<address,list<pair<start,end>>>
	chunks = [] # list<pair<start,end>>
	rangeHookId = {} # dict<pair<start,end>, hookID>, hookID = pair<hookName,xor>
	prodHooks = [] # list<hookID>, hookID = pair<hookName,xor>
	producerChunks = {} # dict<hookID, hookID_product>, hookID = pair<hookName,xor>, hookID_product = pair<list<range>, range>
	producerIds = [] # list<pair<insAddress: int, colour: int>>
	producerIdsChunks = {} # dict<pair<insAddress: int, colour: int>, list<pair<start, end>>>
	colourChunks = {} # dict<int, list<pair<start, end>>>
	# for each consumer
	for consumer in consumers:
		consumers[consumer].sort()
		# for each consumed address by the consumer
		for consumedAddress in consumers[consumer]:
			# if address is in tainted chunks (log files)
			res = searchTaintedChunk(taintProducerRoot, consumedAddress)
			if res is not None:
				currentRange = (res.start, res.end)
				# insert chunk
				if currentRange not in chunks:
					chunks.append(currentRange)
				# insert consumer
				if consumer not in consumerChunks.keys():
					consumerChunks[consumer] = [currentRange]
				else:
					if currentRange not in consumerChunks[consumer]:
						consumerChunks[consumer].append(currentRange)
				# insert producer
				hookID = (res.name, res.xorValue)
				rangeHookId[currentRange] = hookID
				# add hookID to producer set (unique ID in dot file)
				if hookID not in prodHooks:
					prodHooks.append(hookID)
				if hookID not in producerChunks.keys():
					hookID_product = HookIdProduct([currentRange], None)
					producerChunks[hookID] = hookID_product
				else:
					if currentRange not in producerChunks[hookID].hookChunks:
						producerChunks[hookID].hookChunks.append(hookID_product)
			# address is in chunks from fTechnique
			else:
				res = searchTaintedChunk(definitiveChunksRoot, consumedAddress)
				if res is not None:
					currentRange = (res.start, res.end)
					# insert chunk
					if currentRange not in chunks:
						chunks.append(currentRange)
					# insert consumer
					if consumer not in consumerChunks.keys():
						consumerChunks[consumer] = [currentRange]
					else:
						if currentRange not in consumerChunks[consumer]:
							consumerChunks[consumer].append(currentRange)
					# if the producer is in the heuristic output
					if currentRange in rangeProd.keys():
						if rangeProd[currentRange] not in producerIds:
							producerIds.append(rangeProd[currentRange])
						if currentRange not in chunks:
							chunks.append(currentRange) # TODO what changed? see a few lines above
						if rangeProd[currentRange] not in producerIdsChunks.keys():
							producerIdsChunks[rangeProd[currentRange]] = [currentRange]
						else:
							if currentRange not in producerIdsChunks[rangeProd[currentRange]]:
								producerIdsChunks[rangeProd[currentRange]].append(currentRange)
					# if the producer is a special node
					elif res.colour != 0:
						if currentRange not in chunks:
							chunks.append(currentRange)
							if res.colour not in colourChunks.keys():
								colourChunks[res.colour] = [currentRange]
							else:
								if currentRange not in colourChunks[res.colour]:
									colourChunks[res.colour].append(currentRange)

	# define large chunks with more than 10 intervals
	THRESHOLD = 10
	largeChunks = [] # list<pair<start,end>>
	for hookId, hookId_products in producerChunks.items():
		if len(hookId_products.hookChunks) >= THRESHOLD:
			if hookId in prodLargeRange.keys():
				hookId_products.hookLargeChunks = prodLargeRange[hookId]
				if prodLargeRange[hookId] not in largeChunks:
					largeChunks.append(prodLargeRange[hookId])

	# WRITE DOT FILE
	output = ""
	output += "digraph {\n\tnode[shape=box]\n"
	for k, v in consumerChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k) + "\"];\n"
	if output:
		logging.info(output)
	output = ""
	for k, v in producerChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + k[0] + "\n " + hex(k[1]) + "\"];\n"
	if output:
		logging.info(output)
	output = ""

	for k, v in producerIdsChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k[0]) + "\n " + hex(k[1]) + "\"];\n"
	if output:
		logging.info(output)
	output = ""

	for k, v in colourChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k) + "\"];\n"
	if output:
		logging.info(output)
	output = ""

	for chunk in chunks:
		if chunk in rangeHookId.keys():
			it_h = rangeHookId[chunk]
			if it_h in prodLargeRange.keys():
				prodLargeRangeMem = prodLargeRange[it_h]
				if prodLargeRangeMem in largeChunks:
					output += "\"" + hex(id(prodLargeRangeMem)) + "\" [label=\"[" + hex(prodLargeRangeMem[0]) + "-\\n" + hex(prodLargeRangeMem[1]) + "]\"];\n";
				else:
					output += "\"" + hex(id(chunk[0])) + "\" [label=\"[" + hex(chunk[0]) + "-\\n" + hex(chunk[1]) + "]\"];\n"
			else:
				output += "\"" + hex(id(chunk[0])) + "\" [label=\"[" + hex(chunk[0]) + "-\\n" + hex(chunk[1]) + "]\"];\n"
		else:
			output += "\"" + hex(id(chunk[0])) + "\" [label=\"[" + hex(chunk[0]) + "-\\n" + hex(chunk[1]) + "]\"];\n"
	if output:
		logging.info(output)
	output = ""

	# WRITE RELATIONSHIP TO DOT FILE
	lrange_cons = {} # dict<range, list<int>>
	for consumer in consumerChunks.keys():
		rangeMap = consumerChunks[consumer]
		for currentRange in rangeMap:
			if currentRange in rangeHookId.keys():
				hookID = rangeHookId[currentRange]
				if hookID in prodLargeRange.keys():
					largeRange = prodLargeRange[hookID]
					if largeRange in largeChunks:
						if largeRange not in lrange_cons.keys():
							lrange_cons[largeRange] = [consumer]
							output += "\"" + hex(id(largeRange)) + "\" -> \"" + hex(id(consumer)) + "\";\n"
						else:
							if consumer not in lrange_cons[largeRange]:
								lrange_cons[largeRange].append(consumer)
							output += "\"" + hex(id(largeRange)) + "\" -> \"" + hex(id(consumer)) + "\";\n"
					elif currentRange in chunks:
						output += "\"" + hex(id(currentRange[0])) + "\" -> \"" + hex(id(consumer)) + "\";\n"
				elif currentRange in chunks:
					output += "\"" + hex(id(currentRange[0])) + "\" -> \"" + hex(id(consumer)) + "\";\n"
			elif currentRange in chunks:
				output += "\"" + hex(id(currentRange[0])) + "\" -> \"" + hex(id(consumer)) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	lrange_prod = [] # list<range>
	# dict<hookID, hookID_product>, hookID = pair<hookName,xor>, hookID_product = pair<list<range>, range>
	for producer in producerChunks.keys():
		currentHookChunks = producerChunks[producer].hookChunks
		for currentRange in currentHookChunks:
			if currentRange in rangeHookId.keys():
				hookID = rangeHookId[currentRange]
				if hookID in prodLargeRange.keys():
					largeRange = prodLargeRange[hookID]
					if largeRange in largeChunks:
						if largeRange not in lrange_prod:
							lrange_prod.append(largeRange)
							output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(largeRange[0])) + "\";\n"
					elif currentRange in chunks:
						output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
				elif currentRange in chunks:
					output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
			elif currentRange in chunks:
				output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	for prodId in producerIdsChunks.keys():
		ranges = producerIdsChunks[prodId]
		for currentRange in ranges:
			if currentRange in chunks:
				output += "\"" + hex(id(prodId)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	for colour in colourChunks.keys():
		ranges = colourChunks[colour]
		for currentRange in ranges:
			if currentRange in chunks:
				output += "\"" + hex(id(colour)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	output += "}"
	logging.info(output)
	output = ""

	return 0


if __name__ == "__main__":
	main()
