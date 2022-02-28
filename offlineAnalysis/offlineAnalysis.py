from collections import Counter, defaultdict
from dataclasses import dataclass # Python 3.7+
from intervalTree import *
from os import listdir
from os.path import isdir, isfile, join, getsize
import sys
import logging

genLogOffset = None 

def setGenLogOffset(directoryTaintedLogs):
	global genLogOffset
	# 0 for early versions, 2 for recent ones where we have timestamps
	logFiles = [f for f in listdir(directoryTaintedLogs) \
				if isfile(join(directoryTaintedLogs, f)) and "mem" not in f and "ins" not in f]
	for logFile in logFiles:
		filePath = join(directoryTaintedLogs, logFile)
		if getsize(filePath):
			with open(filePath) as f:
				for line in f:
					genLogOffset = 0 if (line[0].isalpha()) else 2
					print(f"Offset to use for indexing logs: {genLogOffset}")
					return

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

@dataclass
class GenLogMemEntry:
	ipAddress: int = 0
	taintColor: int = 0
	opcode: str = None
	memAddress: int = 0
	memSize: int = 0
	assertType: int = 0
	ctxt: int = 0
	callClock: int = 0
	jmpClock: int = 0

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
	callClock = int(splittedLine[0], 16) if idx == 2 else 0
	jmpClock = int(splittedLine[1], 16) if idx == 2 else 0
	ipAddress = int(splittedLine[idx+1], 16)
	taintColor = int(splittedLine[idx+2].replace("[", "").replace("]", ""))
	opcode = splittedLine[idx+3]
	memAddress = int(splittedLine[offsetForAddress].split("(")[0], 16)
	memSize = int(splittedLine[offsetForAddress].split("(")[1].replace(")", ""))
	assertType = int(splittedLine[idx+6])
	ctxt = int(splittedLine[idx+7], 16)
	return GenLogMemEntry(ipAddress, taintColor, opcode, memAddress, memSize, assertType, ctxt, callClock, jmpClock)

def getDictConsumers(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	consumers = defaultdict(set)
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(join(directoryTaintedLogs, logFile)) as f:
				for line in f:
					splittedLine = line.strip().split(" ")
					# consider only taint logs that involves memory areas
					memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
					instructionType = getInstructionTypeForGeneralLog(splittedLine)
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						# BEWARE it is not keeping track of the size here
						genLogMemEntry = parseGeneralLogForMemoryEntry(instructionType, splittedLine)	
						consumers[genLogMemEntry.ipAddress].add(genLogMemEntry.memAddress)
	return consumers

# for now, we do not distinguish consumers by call stack hash
def getDictConsumersByTimestamp(directoryTaintedLogs):
	# note: will break on old logs due to missing timestamp
	if genLogOffset == 0:
		print("Please do not use getDictConsumersByTimestamp on old logs")
		exit(1)
	tempConsumers = defaultdict(list)
	equivConsumers = defaultdict(set)
	logFiles = [f for f in listdir(directoryTaintedLogs) \
				if isfile(join(directoryTaintedLogs, f)) and "mem" not in f and "ins" not in f]
	for logFile in logFiles:
		with open(join(directoryTaintedLogs, logFile)) as f:
			lastTimestamp = -1 # unless we overflow an uint32
			prevConsumer = -1
			lastAddr = -1
			for line in f:
				splittedLine = line.strip().split(" ")
				# consider only taint logs that involves memory areas
				memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
				instructionType = getInstructionTypeForGeneralLog(splittedLine)
				if instructionType in memoryLogs:
					# BEWARE it is not keeping track of the size here
					genLogMemEntry = parseGeneralLogForMemoryEntry(instructionType, splittedLine)
					tempConsumers[genLogMemEntry.ipAddress].append(genLogMemEntry.memAddress)
					# == lastAddr a bit rough as it could be still the same dword, but still...
					if genLogMemEntry.jmpClock == lastTimestamp:
						equivConsumers[prevConsumer].add(genLogMemEntry.ipAddress)
					else:
						lastTimestamp = genLogMemEntry.jmpClock
						prevConsumer = genLogMemEntry.ipAddress
						lastAddr = genLogMemEntry.memAddress
	print(len(equivConsumers))
	print(len(equivConsumers.items()))

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
			with open(join(directoryTaintedLogs, logFile)) as f:
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

def fTechniqueWithProperCounts(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) \
				if isfile(join(directoryTaintedLogs, f)) and "mem" not in f and "ins" not in f]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	addrDictWithCnts = defaultdict(lambda: defaultdict(int)) # dict<memAddr: dict<ins, count>>
	for logFile in logFiles:
		# consider only general taint logs
		with open(join(directoryTaintedLogs, logFile)) as f:
			for line in f:
				splittedLine = line.strip().split(" ")
				instructionType = getInstructionTypeForGeneralLog(splittedLine)
				# consider only the instruction that involves memory areas
				if instructionType in memoryLogs:
					# TODO swap ifs for efficiency
					genLogMemEntry = parseGeneralLogForMemoryEntry(instructionType, splittedLine)
					#  the memory operand is the first
					if instructionType == "reg-mem" and genLogMemEntry.assertType != 1:
						for i in range(0, genLogMemEntry.memSize):
							addrDictWithCnts[genLogMemEntry.memAddress+i][genLogMemEntry.ipAddress] += 1
					elif genLogMemEntry.assertType != 2: # for "mem", "mem-imm" and "mem-reg"
						for i in range(0, genLogMemEntry.memSize):
							addrDictWithCnts[genLogMemEntry.memAddress+i][genLogMemEntry.ipAddress] += 1
	print(f"Size of addrDictWithCnts for fTechniqueLocal: {len(addrDictWithCnts)}")

	# Now calculate "preliminary" chunks
	preliminaryChunks = defaultdict(set)  # dict<int, list<int>> but we do not want duplicates
	# for all bytes in the map
	for memAddr in addrDictWithCnts.keys():
		# (ordered) list of instructions that accessed that byte
		listOfIns = list(addrDictWithCnts[memAddr].keys())
		listOfIns.sort() # TODO sorting for breaking ties? unneeded?
		
		# look for instruction with lowest hitcount
		hitCount = sys.maxsize
		ins = None
		for currentIns in listOfIns: # ins will be picked here
			insCount = addrDictWithCnts[memAddr][currentIns]
			if insCount < hitCount:
				hitCount = insCount
				ins = currentIns
		# add/update instruction in preliminary map
		preliminaryChunks[ins].add(memAddr)
	
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
		totalChunks = totalChunks + len(s)

	print(f"Definitive chunks from fTechniqueLocal: {totalChunks}")
	return definitiveChunks

def fTechnique(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	insCounterDict = defaultdict(int)  # dict<ipAddr: int, size: int> (hit counter)
	byteInsDict = defaultdict(set)  # dict<memAddr: int, list<int>> (set of instruction that accessed that byte)
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(join(directoryTaintedLogs, logFile)) as f:
				for line in f:
					splittedLine = line.strip().split(" ")
					instructionType = getInstructionTypeForGeneralLog(splittedLine)
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						# TODO swap ifs for efficiency
						genLogMemEntry = parseGeneralLogForMemoryEntry(instructionType, splittedLine)
						# for "mem", "mem-imm" and "mem-reg" the memory operand is the first
						if instructionType == "mem" or instructionType == "mem-imm" or instructionType == "mem-reg":
							if genLogMemEntry.assertType != 2:
								insCounterDict[genLogMemEntry.ipAddress] += 1
								for i in range(0, genLogMemEntry.memSize):
									byteInsDict[genLogMemEntry.memAddress+i].add(genLogMemEntry.ipAddress)
						# for "reg-mem" the memory operand is the second
						elif genLogMemEntry.assertType != 1:
							insCounterDict[genLogMemEntry.ipAddress] += 1
							for i in range(0, genLogMemEntry.memSize):
								byteInsDict[genLogMemEntry.memAddress+i].add(genLogMemEntry.ipAddress)
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
	logFiles = [f for f in listdir(directoryTaintedLogs) \
				if isfile(join(directoryTaintedLogs, f)) and "mem" not in f and "ins" not in f]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	rangeProd = {}  # dict<pair<startMem: int, endMem: int>, pair<insAddress: int, color: int>>
	addrCol = {}  # dict<address: int, color: int>
	for logFile in logFiles:
		# consider only general taint logs
		with open(join(directoryTaintedLogs, logFile)) as f:
			for line in f:
				splittedLine = line.strip().split(" ")
				instructionType = getInstructionTypeForGeneralLog(splittedLine)
				# consider only the instruction that involves memory areas
				if instructionType in memoryLogs:
					genLogMemEntry = parseGeneralLogForMemoryEntry(instructionType, splittedLine)
					# process memAddress
					addrCol[genLogMemEntry.memAddress] = genLogMemEntry.taintColor # BEWARE of overwrites
					# if the memory is the destination operand -> it will be overwritten (expect for cmp and test)
					if genLogMemEntry.opcode != "cmp" and genLogMemEntry.opcode != "test" and genLogMemEntry.opcode != "push" and \
							(instructionType == "mem-imm" or instructionType == "mem-reg"):
						res: TaintedChunk = searchTaintedChunk(definitiveChunksRoot, genLogMemEntry.memAddress)
						if res is not None:
							# TODO we had an update operation here, seemed unnecessary
							rangeProd[(res.start, res.end)] = (genLogMemEntry.ctxt, genLogMemEntry.taintColor)
	return rangeProd, addrCol


def main():
	# sanity check
	if len(sys.argv) != 2:
		print("Usage: python offlineAnalysis.py PATH_TO_WRT_LOGS (e.g. offlineAnalysis.py C:\\Pin319\\experiment)")
		return -1

	directoryLogs = sys.argv[1]
	directoryTaintedLogs = join(directoryLogs, "taint")
	callStackLog = join(directoryLogs, "callstack.log")

	# sanity checks
	if isdir(directoryTaintedLogs) is False:
		print("Could not find subdirectory for tainted logs!")
	if isfile(callStackLog) is False:
		print("Could not find call stack log!")

	setGenLogOffset(directoryTaintedLogs)

	# create logging file # TODO why do we even need logging handlers?
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
	cnt = 0
	for l in consumers.values():
		cnt += len(l)
	print(f"Number of consumed addresses to parse: {cnt}")

	#getDictConsumersByTimestamp(directoryTaintedLogs)

	'''
	Create an interval tree that contains the tainted memory areas during the program execution
	'''
	taintProducerRoot, prodLargeRange = populateTaintedChunks(directoryTaintedLogs)

	#definitiveChunks = fTechnique(directoryTaintedLogs)
	#print(len(definitiveChunks.items()))
	definitiveChunks = fTechniqueWithProperCounts(directoryTaintedLogs)
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
	consumerChunks = defaultdict(set) # dict<address,list<pair<start,end>>>
	chunks = set() # list<pair<start,end>>
	rangeHookId = {} # dict<pair<start,end>, hookID>, hookID = pair<hookName,xor>
	##prodHooks = set() # list<hookID>, hookID = pair<hookName,xor>
	producerChunks = {} # dict<hookID, hookID_product>, hookID = pair<hookName,xor>, hookID_product = pair<set<range>, range>
	producerIds = set() # list<pair<insAddress: int, colour: int>>
	producerIdsChunks = defaultdict(set) # dict<pair<insAddress: int, colour: int>, list<pair<start, end>>>
	colourChunks = defaultdict(set) # dict<int, list<pair<start, end>>>
	# for each consumer
	for consumer in consumers:
		tempList = sorted(list(consumers[consumer]))
		# for each consumed address at the consumer
		for consumedAddress in tempList:
			# if address is in tainted chunks (log files)
			res = searchTaintedChunk(taintProducerRoot, consumedAddress)
			if res is not None:
				currentRange = (res.start, res.end)
				# insert chunk
				chunks.add(currentRange) # TODO we may use some order later?
				# insert consumer
				consumerChunks[consumer].add(currentRange)
				# insert producer
				hookID = (res.name, res.xorValue)
				rangeHookId[currentRange] = hookID
				# add hookID to producer set (unique ID in dot file)
				##prodHooks.add(hookID)
				if hookID not in producerChunks.keys():
					producerChunks[hookID] = HookIdProduct(set({currentRange}), None)
				else:
					producerChunks[hookID].hookChunks.add(currentRange) # amended logic error here...
			# address is in chunks from fTechnique
			else:
				res = searchTaintedChunk(definitiveChunksRoot, consumedAddress)
				if res is not None:
					currentRange = (res.start, res.end)
					# insert chunk
					chunks.add(currentRange)
					# insert consumer
					consumerChunks[consumer].add(currentRange)
					# if the producer is in the heuristic output
					if currentRange in rangeProd.keys():
						producerIds.add(rangeProd[currentRange]) # range => set of (ctxt, color) pairs
						#if currentRange not in chunks: # TODO this is likely a leftover from Andrea
						#	chunks.add(currentRange) # was: append
						producerIdsChunks[rangeProd[currentRange]].add(currentRange)
					# if the producer is a special node
					elif res.colour != 0:
						colourChunks[res.colour].add(currentRange) # logic bug fixed (was not added if chunk existed)

	# define large chunks with more than 10 intervals
	THRESHOLD = 10
	largeChunks = set() # list<pair<start,end>>
	for hookId, hookId_products in producerChunks.items():
		if len(hookId_products.hookChunks) >= THRESHOLD:
			if hookId in prodLargeRange.keys():
				hookId_products.hookLargeChunks = prodLargeRange[hookId] # TODO this seems unused by Andrea
				largeChunks.add(prodLargeRange[hookId])

	# quick analysis of how many instructions access the same chunks
	dirtycount_duplicates = set()
	dirtycount_keys = sorted(list(consumerChunks.keys()))
	dirtycount_len = len(dirtycount_keys)
	for i in range(0, dirtycount_len-1):
		if i in dirtycount_duplicates:
			continue # do not count duplicates again
		j = i + 1
		while j < dirtycount_len:
			if Counter(consumerChunks[dirtycount_keys[i]]) == Counter(consumerChunks[dirtycount_keys[j]]):
				dirtycount_duplicates.add(j)
			j = j + 1
	num_duplicates = len(dirtycount_duplicates)
	print(f"Number of instructions with unique ranges: {dirtycount_len-num_duplicates} (duplicates: {num_duplicates}/{dirtycount_len})")
	
	print("Attempting duplicates removal (TODO: unify labels)")
	for idx in dirtycount_duplicates:
		del consumerChunks[dirtycount_keys[idx]]

	## Internal graph representation
	## We will start with something real simple
	my_consumers = set()
	my_chunks = set()
	my_producers = set()
	my_cons_edges = set()
	my_prod_edges = set()

	# WRITE DOT FILE
	output = "digraph {\n\tnode[shape=box]\n"
	logging.info(output)
	output = ""

	tmpChunksCnt = 0
	for k, v in consumerChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k) + "\"];\n"
		tmpChunksCnt = tmpChunksCnt + len(v)
	print(f"Consumer chunks: {len(consumerChunks.items())} (recursively: {tmpChunksCnt})")
	if output:
		logging.info(output)
	output = ""

	tmpChunksCnt = 0
	for k, v in producerChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + k[0] + "\n " + hex(k[1]) + "\"];\n"
		if not (len(v.hookChunks) >= THRESHOLD and k in prodLargeRange.keys()):
			tmpChunksCnt = tmpChunksCnt + len(v.hookChunks)
	print(f"Producer chunks: {len(producerChunks.items())} (recursively: {tmpChunksCnt} non-large)")
	if output:
		logging.info(output)
	output = ""

	tmpChunksCnt = 0
	for k, v in producerIdsChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k[0]) + "\n " + hex(k[1]) + "\"];\n"
		tmpChunksCnt = tmpChunksCnt + len(v)
	print(f"ProducerIDs chunks: {len(producerIdsChunks.items())} (recursively: {tmpChunksCnt})")
	if output:
		logging.info(output)
	output = ""

	tmpChunksCnt = 0
	for k, v in colourChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k) + "\"];\n"
		tmpChunksCnt = tmpChunksCnt + len(v)
	print(f"Colour chunks: {len(colourChunks.items())} (recursively: {tmpChunksCnt})")
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
	print(f"Unique chunks from consumer analysis: {len(chunks)}")
	if output:
		logging.info(output)
	output = ""

	# WRITE RELATIONSHIP TO DOT FILE
	lrange_cons = defaultdict(set) # dict<range, list<int>>
	for consumer in consumerChunks.keys():
		my_consumers.add(consumer) # DBG
		rangeMap = consumerChunks[consumer]
		for currentRange in rangeMap:
			theRange = None
			if currentRange in chunks: # better reassigning than having nested ifs
				theRange = currentRange[0]
			if currentRange in rangeHookId.keys():
				hookID = rangeHookId[currentRange]
				if hookID in prodLargeRange.keys():
					largeRange = prodLargeRange[hookID]
					if largeRange in largeChunks:
						lrange_cons[largeRange].add(consumer)
						theRange = largeRange # other cases: currentRange[0]
			if theRange is not None:
				my_cons_edges.add((theRange, consumer)) # DBG
				my_chunks.add(theRange)
				output += "\"" + hex(id(theRange)) + "\" -> \"" + hex(id(consumer)) + "\";\n"
			else:
				print("Help, did I break something when plotting consumerChunks?")			
	if output:
		logging.info(output)
	output = ""

	lrange_prod = [] # list<range>
	# dict<hookID, hookID_product>, hookID = pair<hookName,xor>, hookID_product = pair<list<range>, range>
	for producer in producerChunks.keys():
		my_producers.add(producer) # DBG
		currentHookChunks = producerChunks[producer].hookChunks
		for currentRange in currentHookChunks:
			theRange = None
			if currentRange in chunks: # better reassigning than having nested ifs
				theRange = currentRange[0]
			if currentRange in rangeHookId.keys():
				hookID = rangeHookId[currentRange]
				if hookID in prodLargeRange.keys():
					largeRange = prodLargeRange[hookID]
					if largeRange in largeChunks:					
						if largeRange not in lrange_prod:
							lrange_prod.append(largeRange)
							theRange = largeRange[0]
						else:
							# TODO no print when already found? or bug from Andrea?!?
							theRange = None
							print("DID ANDREA FORGOT THIS?!?")
			if theRange is not None:
				my_prod_edges.add((producer, theRange)) # DBG
				my_chunks.add(theRange)
				output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(theRange)) + "\";\n"
			else:
				print("Help, did I break something when plotting producerChunks?")
	if output:
		logging.info(output)
	output = ""

	for prodId in producerIdsChunks.keys():
		ranges = producerIdsChunks[prodId]
		for currentRange in ranges:
			if currentRange in chunks:
				my_producers.add(prodId) # DBG
				my_prod_edges.add((prodId, currentRange[0])) # DBG
				my_chunks.add(currentRange[0])
				output += "\"" + hex(id(prodId)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	for colour in colourChunks.keys():
		ranges = colourChunks[colour]
		for currentRange in ranges:
			if currentRange in chunks:
				my_producers.add(colour) # DBG
				my_prod_edges.add((colour, currentRange[0])) # DBG
				my_chunks.add(currentRange[0])
				output += "\"" + hex(id(colour)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	output += "}"
	logging.info(output)
	output = ""

	print("Statistics on graph:")
	print(f"Producer nodes: {len(my_producers)}")
	print(f"Consumer nodes: {len(my_consumers)}")
	print(f"Chunk nodes: {len(my_chunks)}")
	print(f"Producer edges: {len(my_prod_edges)}")
	print(f"Consumer edges: {len(my_cons_edges)}")

	# Scan for chunks that have (same producer and) same consumers
	the_chunks = list(my_chunks)
	the_chunks_num = len(the_chunks)
	the_skip_list = set()

	# dumbie algorithmic: trade space for execution speed :)
	the_scztoon = []
	the_detailed_scztoon = defaultdict(set)
	for i in range(0, the_chunks_num):
		consumers = set([b for (a,b) in my_cons_edges if a == the_chunks[i]])
		the_scztoon.append(Counter(consumers)) # OI OI OI
	for i in range(0, the_chunks_num-1):
		if i in the_skip_list:
			continue # do not analyze previously matched node
		j = i + 1
		while j < the_chunks_num:
			if (the_scztoon[i] == the_scztoon[j]):
				the_detailed_scztoon[i].add(i)
				the_detailed_scztoon[i].add(j)
				the_skip_list.add(j)
			j = j + 1
	''' # slow naive version :)
	for i in range(0, the_chunks_num-1):
		if i in the_skip_list:
			continue # do not analyze previously matched node
		consumers = [b for (a,b) in my_cons_edges if a == the_chunks[i]]
		j = i + 1
		while j < the_chunks_num:
			other_consumers = [b for (a,b) in my_cons_edges if a == the_chunks[j]]
			if (sorted(consumers) == sorted(other_consumers)):
				the_skip_list.add(j)
			j = j + 1
	'''
	print(f"Chunks that can be merged based on uses: {len(the_skip_list)}")
	
	print(f"Candidate groups for merging: {len(the_detailed_scztoon.keys())}")
	lengths = [2, 5, 10, 20]
	for l in lengths:
		cnt = len([x for x in the_detailed_scztoon.values() if len(x) > l])
		print(f"> groups with more than {l} elements: {cnt}")
		if cnt == 0:
			break
	return 0


if __name__ == "__main__":
	main()
