# ARM Opcode Assemble for IDA Plugin
# Author : Khiemnnm
# Last update : 04/Feb/2015
# History log
# + 04/Feb/2015 : First version
#
import idaapi
import idautils
import idc
import sys

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Arm Opcode Assembler helper"
    help = "This is help"
    wanted_name = "ARM Opcode Assembler"
    wanted_hotkey = "Alt-A"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
    	startarm()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))

def remove_doublespace(str):
	pos = str.find("  ")
	while pos != -1:
		str = str.replace("  "," ")
		pos = str.find("  ")
	return str

def clean_part(str):
	str = str.strip()
	pos = str.find(' ')
	while pos != -1:
		str = str.replace(' ','')
		pos = str.find(' ')
	return str

def read_number(str):
	err_flag = 0
	try:
		err_flag = 0
		num = int(str)
	except ValueError:
		err_flag = 1
		num = 0

	if err_flag == 1:
		try:
			err_flag = 0
			num = int(str,16)
		except ValueError:
			err_flag = 1
			num = 0

	if err_flag == 1:
		try:
			err_flag = 0
			num = int(str,2)
		except ValueError:
			err_flag = 1
			num = 0

	if err_flag == 1:
		raise ValueError("Error: Could not read number in"+str)

	return num

def remove_prefix(prefix,str):
	if str.startswith(prefix):
		str = str[len(prefix):]
	return str

def get_cond_bit(cond_str):
	if cond_str == "eq":
		cond = "0000"
	elif cond_str == "ne":
		cond = "0001"
	elif cond_str == "cs":
		cond = "0010"
	elif cond_str == "cc":
		cond = "0011"
	elif cond_str == "mi":
		cond = "0100"
	elif cond_str == "pl":
		cond = "0101"
	elif cond_str == "vs":
		cond = "0110"
	elif cond_str == "vc":
		cond = "0111"
	elif cond_str == "hi":
		cond = "1000"
	elif cond_str == "ls":
		cond = "1001"
	elif cond_str == "ge":
		cond = "1010"
	elif cond_str == "lt":
		cond = "1011"
	elif cond_str == "gt":
		cond = "1100"
	elif cond_str == "le":
		cond = "1101"
	elif cond_str == "al":
		cond = "1110"
	else:
		cond = "1110"
	return cond

def get_Rn_bit(Rn_str):
	RnStr_ = Rn_str
	if RnStr_ == "sp":
		RnStr_ = 'r13'
	elif RnStr_ == "lr":
		RnStr_ = 'r14'
	elif RnStr_ == "pc":
		RnStr_ = 'r15'

	n = int(remove_prefix("r",RnStr_))
	return format(n,'b').zfill(4)

def get_args(arg_str):
	parts = arg_str.split(',')
	for i in range(0,len(parts)):
		parts[i] = clean_part(parts[i])
	return parts

def bx_opcode(startea, part):
	cond_str = remove_prefix("bx",part[0])
	cond = get_cond_bit(cond_str)
	Rn = get_Rn_bit(part[1])
	ins_str = cond + '0001' + '0010' + '1111' + '1111' + '1111' + '0001' + Rn
	ins_value = int(ins_str,2)
	PatchDword(startea, ins_value)

def bandbl_opcode(startea, part):
	dest_addr =  read_number(part[1]);
	offset = dest_addr - startea - 8
	offset = offset >> 2
	if part[0] == "bl":
			linkbit = '1'
	elif part[0] in ('b','ble','bls','blt'):
		linkbit = '0'
	else:
		if part[0].startswith("bl"):
			linkbit = '1'
		else:
			linkbit = '0'

	if part[0].startswith("bl") and len(part[0]) == 4:
			cond_str = remove_prefix("bl",part[0])
	else:
		cond_str = remove_prefix("b",part[0])

	cond = get_cond_bit(cond_str)
	ins_str = cond + '101' + linkbit
	ins_value = int(ins_str,2) << 24
	delta = offset & 0x00ffffff
	ins_value = ins_value | delta
	PatchDword(startea, ins_value)

def dataprocessing_opcode(startea, part):
	if part[0] == "and":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '0000'
		imm_operand = '0'
		setcondcode = '0'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[2].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "eor":
		raise ValueError("Error: Not implement "+str)
	elif part[0] == "sub":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '0010'
		imm_operand = '0'
		setcondcode = '0'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[2].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "rsb":
		raise ValueError("Error: Not implement "+str)
	elif part[0] == "add":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '0100'
		imm_operand = '0'
		setcondcode = '0'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[2].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "adc":
		raise ValueError("Error: Not implement "+str)
	elif part[0] == "sbc":
		raise ValueError("Error: Not implement "+str)
	elif part[0] == "rsc":
		raise ValueError("Error: Not implement "+str)
	elif part[0] == "tst":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1000'
		imm_operand = '0'
		setcondcode = '1'
		Rn = get_Rn_bit(args[0])
		Rd = '0000' #get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[1].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[1])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[1])
	elif part[0] == "teq":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1001'
		imm_operand = '0'
		setcondcode = '1'
		Rn = get_Rn_bit(args[0])
		Rd = '0000' #get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[1].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[1])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[1])
	elif part[0] == "cmp":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1010'
		imm_operand = '0'
		setcondcode = '1'
		Rn = get_Rn_bit(args[0])
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[1].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[1])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[1])
	elif part[0] == "cmn":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1011'
		imm_operand = '0'
		setcondcode = '1'
		Rn = get_Rn_bit(args[0])
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[1].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[1])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[1])
	elif part[0] == "orr":
		raise ValueError("Error: Not implement "+str)
	elif part[0] == "mov":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1101'
		imm_operand = '0'
		setcondcode = '0'
		Rn = '0000'
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[1].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[1])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[1])
	elif part[0] == "bic":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1110'
		imm_operand = '0'
		setcondcode = '0'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[2].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "mvn":
		args = get_args(part[1])
		cond =  '1110'
		opcode = '1111'
		imm_operand = '0'
		setcondcode = '0'
		Rn = '0000'
		Rd = get_Rn_bit(args[0])
		operand2 = '000000000000'
		if args[1].startswith("#"):
			imm_operand = '1'
			imm_str = remove_prefix("#",args[1])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			operand2 = '0000' + format(imm_value,'b').zfill(8)
		else:	
			imm_operand = '0'
			operand2 = '00000000' + get_Rn_bit(args[1])

	ins_str = cond + '00' + imm_operand + opcode + setcondcode + Rn + Rd + operand2 
	ins_value = int(ins_str,2)
	PatchDword(startea, ins_value)

def singledatatransfer_opcode(startea, part):
	if part[0] == "str":
		part1 = part[1].replace('[','')
		part1 = part1.replace(']','')
		args = get_args(part1)
		cond =  '1110'
		immediaOffset = '0'
		prepostIndexbit = '1'
		updownbit = '1'
		bytewordbit = '0'
		writebackbit = '0'
		loadstorebit = '0'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		offset = '000000000000'
		if args[2].startswith("#"):
			immediaOffset = '0'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			offset = format(imm_value,'b').zfill(12)
		else:	
			immediaOffset = '1'
			offset = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "strb":
		part1 = part[1].replace('[','')
		part1 = part1.replace(']','')
		args = get_args(part1)
		cond =  '1110'
		immediaOffset = '0'
		prepostIndexbit = '1'
		updownbit = '1'
		bytewordbit = '1'
		writebackbit = '0'
		loadstorebit = '0'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		offset = '000000000000'
		if args[2].startswith("#"):
			immediaOffset = '0'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			offset = format(imm_value,'b').zfill(12)
		else:	
			immediaOffset = '1'
			offset = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "ldr":
		part1 = part[1].replace('[','')
		part1 = part1.replace(']','')
		args = get_args(part1)
		cond =  '1110'
		immediaOffset = '0'
		prepostIndexbit = '1'
		updownbit = '1'
		bytewordbit = '0'
		writebackbit = '0'
		loadstorebit = '1'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		offset = '000000000000'
		if args[2].startswith("#"):
			immediaOffset = '0'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			offset = format(imm_value,'b').zfill(12)
		else:	
			immediaOffset = '1'
			offset = '00000000' + get_Rn_bit(args[2])
	elif part[0] == "ldrb":
		part1 = part[1].replace('[','')
		part1 = part1.replace(']','')
		args = get_args(part1)
		cond =  '1110'
		immediaOffset = '0'
		prepostIndexbit = '1'
		updownbit = '1'
		bytewordbit = '1'
		writebackbit = '0'
		loadstorebit = '1'
		Rn = get_Rn_bit(args[1])
		Rd = get_Rn_bit(args[0])
		offset = '000000000000'
		if args[2].startswith("#"):
			immediaOffset = '0'
			imm_str = remove_prefix("#",args[2])
			imm_value = read_number(imm_str)
			imm_value = imm_value & 0xFF
			offset = format(imm_value,'b').zfill(12)
		else:	
			immediaOffset = '1'
			offset = '00000000' + get_Rn_bit(args[2])

	ins_str = cond + '01' + immediaOffset + prepostIndexbit + updownbit + bytewordbit + writebackbit + loadstorebit + Rn + Rd + offset
	ins_value = int(ins_str,2)
	PatchDword(startea, ins_value)

def arm(startea,instruction_string):
	#startea = idc.ScreenEA()
	instruction_string = instruction_string.lower()
	instruction_string = remove_doublespace(instruction_string)
	part = instruction_string.split(' ',1)
	for i in range(0,len(part)):
		part[i] = clean_part(part[i])

	if part[0] in ('and','eor','sub','rsb','add','adc','sbc','rsc','tst','teq','cmp','cmn','orr','mov','bic','movn'):
		dataprocessing_opcode(startea,part)
	elif part[0].startswith("bx"):
		bx_opcode(startea,part)
	elif part[0].startswith("b"):
		bandbl_opcode(startea,part)
	elif part[0] in ('ldr','str','ldrb','strb'):
		singledatatransfer_opcode(startea,part)

def startarm():
	curEA = idc.ScreenEA()
	isCont = 1
	while isCont:
		str = AskStr("","Address :"+hex(curEA)+"\nInstruction")
		if str:
			arm(curEA,str)
			curEA = curEA + 4
		else:
			isCont = 0
