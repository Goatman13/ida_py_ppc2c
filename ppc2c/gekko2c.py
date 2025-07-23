# Gekko To C

from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc


def ps_abs(frD, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d} & 0x7FFFFFFF".format(frD,frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_add(frD, frA, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d} + f{:d}".format(frD, frA, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_cmpo0(crD, frA, frB):

	string  = ".\ncr{:d} = 0".format(crD)
	string += "\ncr{:d}.lt = f{:d}[0]  < f{:d}[0]".format(crD, frA, frB)
	string += "\ncr{:d}.gt = f{:d}[0]  > f{:d}[0]".format(crD, frA, frB)
	string += "\ncr{:d}.eq = f{:d}[0] == f{:d}[0]".format(crD, frA, frB)
	string += "\ncr{:d}.so = f{:d}[0] == NaN || f{:d}[0] == NaN".format(crD, frA, frB)
	return string

def ps_cmpo1(crD, frA, frB):

	string  = ".\ncr{:d} = 0".format(crD)
	string += "\ncr{:d}.lt = f{:d}[1]  < f{:d}[1]".format(crD, frA, frB)
	string += "\ncr{:d}.gt = f{:d}[1]  > f{:d}[1]".format(crD, frA, frB)
	string += "\ncr{:d}.eq = f{:d}[1] == f{:d}[1]".format(crD, frA, frB)
	string += "\ncr{:d}.so = f{:d}[1] == NaN || f{:d}[1] == NaN".format(crD, frA, frB)
	return string

def ps_cmpu0(crD, frA, frB):

	string  = ".\ncr{:d} = 0".format(crD)
	string += "\ncr{:d}.lt = f{:d}[0]  < f{:d}[0]".format(crD, frA, frB)
	string += "\ncr{:d}.gt = f{:d}[0]  > f{:d}[0]".format(crD, frA, frB)
	string += "\ncr{:d}.eq = f{:d}[0] == f{:d}[0]".format(crD, frA, frB)
	string += "\ncr{:d}.so = f{:d}[0] == NaN || f{:d}[0] == NaN".format(crD, frA, frB)
	return string

def ps_cmpu1(crD, frA, frB):

	string  = ".\ncr{:d} = 0".format(crD)
	string += "\ncr{:d}.lt = f{:d}[1]  < f{:d}[1]".format(crD, frA, frB)
	string += "\ncr{:d}.gt = f{:d}[1]  > f{:d}[1]".format(crD, frA, frB)
	string += "\ncr{:d}.eq = f{:d}[1] == f{:d}[1]".format(crD, frA, frB)
	string += "\ncr{:d}.so = f{:d}[1] == NaN || f{:d}[1] == NaN".format(crD, frA, frB)
	return string

def ps_div(frD, frA, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d} / f{:d}".format(frD, frA, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_madd(frD, frA, frC, frB, Rc):

	string = "f{:d}[2xfloat] = (f{:d} * f{:d}) + f{:d}".format(frD, frA, frC, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_madds0(frD, frA, frC, frB, Rc):

	string = ".\nf{:d}[0] = (f{:d}[0] * f{:d}[0]) + f{:d}[0]".format(frD, frA, frC, frB)
	string += "\nf{:d}[1] = (f{:d}[1] * f{:d}[0]) + f{:d}[1]".format(frD, frA, frC, frB)
	if(Rc):
		string += "\ncr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_madds1(frD, frA, frC, frB, Rc):

	string = ".\nf{:d}[0] = (f{:d}[0] * f{:d}[1]) + f{:d}[0]".format(frD, frA, frC, frB)
	string += "\nf{:d}[1] = (f{:d}[1] * f{:d}[1]) + f{:d}[1]".format(frD, frA, frC, frB)
	if(Rc):
		string += "\ncr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_merge00(frD, frA, frB, Rc):

	string = "f{:d}[0] = f{:d}[0], f{:d}[1] = f{:d}[0]".format(frD, frA, frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_merge01(frD, frA, frB, Rc):

	string = "f{:d}[0] = f{:d}[0], f{:d}[1] = f{:d}[1]".format(frD, frA, frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_merge10(frD, frA, frB, Rc):

	string = "f{:d}[0] = f{:d}[1], f{:d}[1] = f{:d}[0]".format(frD, frA, frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_merge11(frD, frA, frB, Rc):

	string = "f{:d}[0] = f{:d}[1], f{:d}[1] = f{:d}[1]".format(frD, frA, frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_mr(frD, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d}".format(frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_msub(frD, frA, frC, frB, Rc):

	string = "f{:d}[2xfloat] = (f{:d} * f{:d}) - f{:d}".format(frD, frA, frC, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_mul(frD, frA, frC, Rc):

	string = "f{:d}[2xfloat] = f{:d} * f{:d}".format(frD, frA, frC)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_muls0(frD, frA, frC, Rc):

	string = ".\nf{:d}[0] = f{:d}[0] * f{:d}[0]".format(frD, frA, frC)
	string += "\nf{:d}[1] = f{:d}[1] * f{:d}[0]".format(frD, frA, frC)
	if(Rc):
		string += "\ncr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_muls1(frD, frA, frC, Rc):

	string = ".\nf{:d}[0] = f{:d}[0] * f{:d}[1]".format(frD, frA, frC)
	string += "\nf{:d}[1] = f{:d}[1] * f{:d}[1]".format(frD, frA, frC)
	if(Rc):
		string += "\ncr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_nabs(frD, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d} | 0x80000000".format(frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_neg(frD, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d} ^ 0x80000000".format(frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_nmadd(frD, frA, frC, frB, Rc):

	string = "f{:d}[2xfloat] = -((f{:d} * f{:d}) + f{:d})".format(frD, frA, frC, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_nmsub(frD, frA, frC, frB, Rc):

	string = "f{:d}[2xfloat] = -((f{:d} * f{:d}) - f{:d})".format(frD, frA, frC, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_res(frD, frB, Rc):

	string = "f{:d}[2xfloat] = ReciprocalEstimate(f{:d})".format(frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_rsqrte(frD, frB, Rc):

	string = "f{:d}[2xfloat] = ReciprocalSquareRootEstimate(f{:d})".format(frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_set(frD, frA, frC, frB, Rc):

	string = "[2xfloat] if f{:d} >= 0.0 then f{:d} = f{:d}, else f{:d} = f{:d}".format(frA, frD, frC, frD, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_sub(frD, frA, frB, Rc):

	string = "f{:d}[2xfloat] = f{:d} - f{:d}".format(frD, frA, frB)
	if(Rc):
		string += ", cr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_sum0(frD, frA, frC, frB, Rc):

	string = ".\nf{:d}[0] = f{:d}[0] + f{:d}[1]".format(frD, frA, frB)
	string += "\nf{:d}[1] = f{:d}[1]".format(frD, frC)
	if(Rc):
		string += "\ncr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

def ps_sum1(frD, frA, frC, frB, Rc):

	string  = "\nf{:d}[0] = f{:d}[0]".format(frD, frC)
	string += ".\nf{:d}[1] = f{:d}[0] + f{:d}[1]".format(frD, frA, frB)
	if(Rc):
		string += "\ncr1[lt,gt,eq,so] = fpscr[fx,fex,vx,ox]"
	return string

# load/store, hard to explain without known gqr values...

def GekkoAsm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	
	# Remove record bit if exist,
	# we need to do this before testing for opcode validity.
	dot = opcode_name.find(".")
	if(dot != -1):
		opcode_name = opcode_name[0:dot]
	
	frA     = (opcode >> 16) & 0x1F
	frB     = (opcode >> 11) & 0x1F
	frC     = (opcode >> 6 ) & 0x1F
	frD     = (opcode >> 21) & 0x1F
	crD     = (opcode >> 23) & 7
	Rc      = opcode & 1

	if   opcode_name == "ps_abs":       return ps_abs(frD, frB, Rc)
	elif opcode_name == "ps_add":       return ps_add(frD, frA, frB)
	elif opcode_name == "ps_cmpo0":     return ps_cmpo0(crD, frA, frB)
	elif opcode_name == "ps_cmpo1":     return ps_cmpo1(crD, frA, frB)
	elif opcode_name == "ps_cmpu0":     return ps_cmpu0(crD, frA, frB)
	elif opcode_name == "ps_cmpu1":     return ps_cmpu1(crD, frA, frB)
	elif opcode_name == "ps_div":       return ps_div(frD, frA, frB, Rc)
	elif opcode_name == "ps_madd":      return ps_madd(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_madds0":    return ps_madds0(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_madds1":    return ps_madds1(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_merge00":   return ps_merge00(frD, frA, frB, Rc)
	elif opcode_name == "ps_merge01":   return ps_merge01(frD, frA, frB, Rc)
	elif opcode_name == "ps_merge10":   return ps_merge10(frD, frA, frB, Rc)
	elif opcode_name == "ps_merge11":   return ps_merge11(frD, frA, frB, Rc)
	elif opcode_name == "ps_mr":        return ps_mr(frD, frB, Rc)
	elif opcode_name == "ps_msub":      return ps_msub(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_mul":       return ps_mul(frD, frA, frC, Rc)
	elif opcode_name == "ps_muls0":     return ps_muls0(frD, frA, frC, Rc)
	elif opcode_name == "ps_muls1":     return ps_muls1(frD, frA, frC, Rc)
	elif opcode_name == "ps_nabs":      return ps_nabs(frD, frB, Rc)
	elif opcode_name == "ps_neg":       return ps_neg(frD, frB, Rc)
	elif opcode_name == "ps_nmadd":     return ps_nmadd(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_nmsub":     return ps_nmsub(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_res":       return ps_res(frD, frB, Rc)
	elif opcode_name == "ps_rsqrte":    return ps_rsqrte(frD, frB, Rc)
	elif opcode_name == "ps_set":       return ps_set(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_sub":       return ps_sub(frD, frA, frB, Rc)
	elif opcode_name == "ps_sum0":      return ps_sum0(frD, frA, frC, frB, Rc)
	elif opcode_name == "ps_sum1":      return ps_sum1(frD, frA, frC, frB, Rc)

	return 0