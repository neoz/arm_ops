import ply.yacc as yacc
from lexer import tokens

def p_line(p):
	'line : command'
	p[0] = ('', p[1])

#############
# argument
#############

def p_argument_h(p):
	'argument : HEXNUM'
	p[0] = p[1]


def p_argument_i(p):
	'argument : CONSTNUM'
	p[0] = p[1]

def p_argument_r(p):
	'argument : register'
	p[0] = p[1]

def p_argument_c(p):
	'argument : CHAR'
	p[0] = p[1]

#############
# register
#############

def p_register(p):
	'register : REGISTER'
	p[0] = p[1]

def p_register_fp(p):
	'register : FP'
	p[0] = 11
def p_register_fp(p):
	'register : IP'
	p[0] = 12

def p_register_sp(p):
	'register : SP'
	p[0] = 13

def p_register_lr(p):
	'register : LR'
	p[0] = 14

def p_register_pc(p):
	'register : PC'
	p[0] = 15

###########
# target
###########

def p_target_imm(p):
	'target : IMMTARGET'
	p[0] = p[1]

def p_target_immhex(p):
	'target : IMMHEXTARGET'
	p[0] = p[1]

################
# branchtarget
################

def p_branchtarget_addr(p):
	'branchtarget : register'
	p[0] = p[1]


def p_error(p):
	#debugger.set_trace()
	print "Error: Unexpected %s token on line %i, but the error may be before this point."%(p.type, p.lineno)
	line = p.lexer.lexdata.split("\n")[p.lineno-1]
	print line
	exit(1)

######
# BRANCH
######
def p_brch(p):
	'command : B branchtarget'
	(ins, con, s, other) = p[1]
	p[0] = 'AAAAA' #instruction.B(other, con, p[2])

parser = yacc.yacc()

def test():
	while True:
		try:
			s = raw_input('instr > ')
		except EOFError:
			break
		if not s: continue
		instr = parser.parse(s)
		print instr

test()