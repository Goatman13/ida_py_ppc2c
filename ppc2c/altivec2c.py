# Altivec To C

from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc

def exp2(j):
	i = 0
	r = 1
	while i < j:
		r *= 2
		i += 1
	return "{:.1f}".format(r)

def sign_extend_imm5(_8_16, value):

	if value & 0x10 == 0x10:
		value = (0xFFFFFFF0 | value & 0xF)
	else:
		value &= 0xF
	if _8_16 == 1:
		value &= 0xFF
	elif _8_16 == 2:
		value &= 0xFFFF
	return value

def imm5_to_signed_string(value):

	sign = ""
	imm = value & 0x1F
	if (imm > 0xF):
		imm = ~imm
		imm &= 0xF
		imm += 1
		sign = "-"
	return sign + "0x{:X}".format(imm)

def vaddcuw(vD, vA, vB):

	return "[4x32b] if v{:d} + v{:d} > 0xFFFFFFFF: v{:d} = 1, else v{:d} = 0".format(vA, vB, vD, vD)

def vaddfp(vD, vA, vB):

	return "v{:d}[4xfloat] = v{:d} + v{:d}".format(vD, vA, vB)

def vaddsbs(vD, vA, vB):

	return "v{:d}[16x8b][s] = v{:d} + v{:d}. if abs(v{:d}) > 0x7F: v{:d} = 0x7F | sign".format(vD, vA, vB, vD, vD)

def vaddshs(vD, vA, vB):

	return "v{:d}[8x16b][s] = v{:d} + v{:d}. if abs(v{:d}) > 0x7FFF: v{:d} = 0x7FFF | sign".format(vD, vA, vB, vD, vD)

def vaddsws(vD, vA, vB):

	return "v{:d}[4x32b][s] = v{:d} + v{:d}. if abs(v{:d}) > 0x7FFFFFFF: v{:d} = 0x7FFFFFFF | sign".format(vD, vA, vB, vD, vD)

def vaddubm(vD, vA, vB):

	return "v{:d}[16x8b][u] = v{:d} + v{:d}".format(vD, vA, vB)

def vadduhm(vD, vA, vB):

	return "v{:d}[8x16b][u] = v{:d} + v{:d}".format(vD, vA, vB)

def vadduwm(vD, vA, vB):

	return "v{:d}[4x32b][u] = v{:d} + v{:d}".format(vD, vA, vB)

def vaddubs(vD, vA, vB):

	return "v{:d}[16x8b] = v{:d} + v{:d}. if v{:d} > 0xFF: v{:d} = 0xFF".format(vD, vA, vB, vD, vD)

def vadduhs(vD, vA, vB):

	return "v{:d}[8x16b] = v{:d} + v{:d}. if v{:d} > 0xFFFF: v{:d} = 0xFFFF".format(vD, vA, vB, vD, vD)

def vadduws(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} + v{:d}. if v{:d} > 0xFFFFFFFF: v{:d} = 0xFFFFFFFF".format(vD, vA, vB, vD, vD)

def vand(vD, vA, vB):

	return "v{:d}[128b] = v{:d} & v{:d}".format(vD, vA, vB)

def vandc(vD, vA, vB):

	return "v{:d}[128b] = v{:d} & ~v{:d}".format(vD, vA, vB)

def vavgsb(vD, vA, vB):

	return "v{:d}[16x8b][s] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 9 bits value)".format(vD, vA, vB)

def vavgsh(vD, vA, vB):

	return "v{:d}[8x16b][s] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 17 bits value)".format(vD, vA, vB)

def vavgsw(vD, vA, vB):

	return "v{:d}[4x32b][s] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 33 bits value)".format(vD, vA, vB)

def vavgub(vD, vA, vB):

	return "v{:d}[16x8b] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 9 bits value)".format(vD, vA, vB)

def vavguh(vD, vA, vB):

	return "v{:d}[8x16b] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 17 bits value)".format(vD, vA, vB)

def vavguw(vD, vA, vB):

	return "v{:d}[4x32b] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 33 bits value)".format(vD, vA, vB)

#todo verify cvts
def vcfsx(vD, imm, vB):

	imm    = exp2(imm)
	return "v{:d}[4xfloat] = (float)(s32)v{:d} / ".format(vD, vB) + imm

def vcfux(vD, imm, vB):

	imm    = exp2(imm)
	return "v{:d}[4xfloat] = (float)(u32)v{:d} / ".format(vD, vB) + imm

def vcmpbfp(vD, vA, vB, vRc):

	cmt    = ".\n[4xfloat] v{:d} = 0\n".format(vD)
	cmt   += "if v{:d} >  v{:d} then v{:d} |= 0x80000000\n".format(vA, vB, vD)
	cmt   += "if v{:d} < -v{:d} then v{:d} |= 0x40000000\n".format(vA, vB, vD)
	if vRc == 1:
		cmt += "cr6 = 0, if v{:d}[128b] = 0x00000000:00000000:00000000:00000000, CR6.eq = 1".format(vD)
	return cmt

def vcmpeqfp(vD, vA, vB, vRc):

	cmt    = "[4xfloat] if v{:d} == v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[4xfloat] if v{:d} == v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpequb(vD, vA, vB, vRc):

	cmt    = "[16x8b] if v{:d} == v{:d then v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[16x8b] if v{:d} == v{:d then v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpequh(vD, vA, vB, vRc):

	cmt    = "[8x16b] if v{:d} == v{:d} then v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[8x16b] if v{:d} == v{:d} then v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpequw(vD, vA, vB, vRc):

	cmt    = "[4x32b] if v{:d} == v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[4x32b] if v{:d} == v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpgefp(vD, vA, vB, vRc):

	cmt    = "[4xfloat] if v{:d} >= v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[4xfloat] if v{:d} >= v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt
	
def vcmpgtfp(vD, vA, vB, vRc):

	cmt    = "[4xfloat] if v{:d} > v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[4xfloat] if v{:d} > v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt
	
def vcmpgtsb(vD, vA, vB, vRc):

	cmt    = "[16x8b][s] if v{:d} > v{:d then v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[16x8b][s] if v{:d} > v{:d then v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpgtsh(vD, vA, vB, vRc):

	cmt    = "[8x16b][s] if v{:d} > v{:d} then v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[8x16b][s] if v{:d} > v{:d} then v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpgtsw(vD, vA, vB, vRc):

	cmt    = "[4x32b][s] if v{:d} > v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[4x32b][s] if v{:d} > v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpgtub(vD, vA, vB, vRc):

	cmt    = "[16x8b] if v{:d} > v{:d then v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[16x8b] if v{:d} > v{:d then v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpgtuh(vD, vA, vB, vRc):

	cmt    = "[8x16b] if v{:d} > v{:d} then v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[8x16b] if v{:d} > v{:d} then v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

def vcmpgtuw(vD, vA, vB, vRc):

	cmt    = "[4x32b] if v{:d} > v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt  = ".\ncr6 = 0"
		cmt += "\n[4x32b] if v{:d} > v{:d} then v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
		cmt += "\nif v{:d}[128b] == 0x00000000:00000000:00000000:00000000 then cr6.eq = 1".format(vD)
		cmt += "\nif v{:d}[128b] == 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FFFFFFFF then cr6.lt = 1".format(vD)
	return cmt

#todo verify cvts
def vctsxs(vD, imm, vB):

	imm    = exp2(imm)
	return "v{:d}[4x32b] = (s32)((float)v{:d} * ".format(vD, vB) + imm + ")"

def vctuxs(vD, imm, vB):

	imm    = exp2(imm)
	return "v{:d}[4x32b] = (u32)((float)v{:d} * ".format(vD, vB) + imm + ")"

def vlogefp(vD, vB):

	return "v{:d}[4xfloat] = log2(v{:d})".format(vD, vB)

def vexptefp(vD, vB):

	return "v{:d}[4xfloat] = exp2(v{:d})".format(vD, vB)

def vmaddfp(vD, vA, vB, vC):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) + v{:d}".format(vD, vA, vC, vB)

def vmaxfp(vD, vA, vB):

	return "[4xfloat] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxsb(vD, vA, vB):

	return "[16x8b][s] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxsh(vD, vA, vB):

	return "[8x16b][s] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxsw(vD, vA, vB):

	return "[4x32b][s] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxub(vD, vA, vB):

	return "[16x8b] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxuh(vD, vA, vB):

	return "[8x16b] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxuw(vD, vA, vB):

	return "[4x32b] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmhaddshs(vD, vA, vB, vC):

	return "v{:d}[8x16b][s] = ((s32)(v{:d} * v{:d}) >> 16) + v{:d} if abs(v{:d}) > 0x7FFF: v{:d} = 0x7FFF | sign".format(vD, vA, vC, vB)

#todo check
def vmhraddshs(vD, vA, vB, vC):

	return "v{:d}[8x16b][s] = (((s32)(v{:d} * v{:d}) + 0x4000) >> 16) + v{:d} if abs(v{:d}) > 0x7FFF: v{:d} = 0x7FFF | sign".format(vD, vA, vC, vB)

def vminfp(vD, vA, vB):

	return "[4xfloat] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminsb(vD, vA, vB):

	return "[16x8b][s] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminsh(vD, vA, vB):

	return "[8x16b][s] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminsw(vD, vA, vB):

	return "[4x32b][s] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminub(vD, vA, vB):

	return "[16x8b] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminuh(vD, vA, vB):

	return "[8x16b] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminuw(vD, vA, vB):

	return "[4x32b] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmladduhm(vD, vA, vB, vC):

	return "v{:d}[8x16b][u] = ((v{:d} * v{:d}) + v{:d}) & 0xFFFF".format(vD, vA, vB, vC)

def vmrghb(vD, vA, vB):

	cmt    = ".\n"
	cmt   += "v{:d}[0].byte  = v{:d}[0].byte\n".format(vD, vA)
	cmt   += "v{:d}[1].byte  = v{:d}[0].byte\n".format(vD, vB)
	cmt   += "v{:d}[2].byte  = v{:d}[1].byte\n".format(vD, vA)
	cmt   += "v{:d}[3].byte  = v{:d}[1].byte\n".format(vD, vB)
	cmt   += "v{:d}[4].byte  = v{:d}[2].byte\n".format(vD, vA)
	cmt   += "v{:d}[5].byte  = v{:d}[2].byte\n".format(vD, vB)
	cmt   += "v{:d}[6].byte  = v{:d}[3].byte\n".format(vD, vA)
	cmt   += "v{:d}[7].byte  = v{:d}[3].byte\n".format(vD, vB)
	cmt   += "v{:d}[8].byte  = v{:d}[4].byte\n".format(vD, vA)
	cmt   += "v{:d}[9].byte  = v{:d}[4].byte\n".format(vD, vB)
	cmt   += "v{:d}[10].byte = v{:d}[5].byte\n".format(vD, vA)
	cmt   += "v{:d}[11].byte = v{:d}[5].byte\n".format(vD, vB)
	cmt   += "v{:d}[12].byte = v{:d}[6].byte\n".format(vD, vA)
	cmt   += "v{:d}[13].byte = v{:d}[6].byte\n".format(vD, vB)
	cmt   += "v{:d}[14].byte = v{:d}[7].byte\n".format(vD, vA)
	cmt   += "v{:d}[15].byte = v{:d}[7].byte".format(vD, vB)
	return cmt

def vmrghh(vD, vA, vB):

	cmt    = ".\n"
	cmt   += "v{:d}[0].half = v{:d}[0].half\n".format(vD, vA)
	cmt   += "v{:d}[1].half = v{:d}[0].half\n".format(vD, vB)
	cmt   += "v{:d}[2].half = v{:d}[1].half\n".format(vD, vA)
	cmt   += "v{:d}[3].half = v{:d}[1].half\n".format(vD, vB)
	cmt   += "v{:d}[4].half = v{:d}[2].half\n".format(vD, vA)
	cmt   += "v{:d}[5].half = v{:d}[2].half\n".format(vD, vB)
	cmt   += "v{:d}[6].half = v{:d}[3].half\n".format(vD, vA)
	cmt   += "v{:d}[7].half = v{:d}[3].half".format(vD, vB)
	return cmt

def vmrghw(vD, vA, vB):

	cmt    = ".\n"
	cmt   += "v{:d}[0].word = v{:d}[0].word\n".format(vD, vA)
	cmt   += "v{:d}[1].word = v{:d}[0].word\n".format(vD, vB)
	cmt   += "v{:d}[2].word = v{:d}[1].word\n".format(vD, vA)
	cmt   += "v{:d}[3].word = v{:d}[1].word".format(vD, vB)
	return cmt

def vmrglb(vD, vA, vB):

	cmt    = ".\n"
	cmt   += "v{:d}[0].byte  = v{:d}[8].byte\n".format(vD, vA)
	cmt   += "v{:d}[1].byte  = v{:d}[8].byte\n".format(vD, vB)
	cmt   += "v{:d}[2].byte  = v{:d}[9].byte\n".format(vD, vA)
	cmt   += "v{:d}[3].byte  = v{:d}[9].byte\n".format(vD, vB)
	cmt   += "v{:d}[4].byte  = v{:d}[10].byte\n".format(vD, vA)
	cmt   += "v{:d}[5].byte  = v{:d}[10].byte\n".format(vD, vB)
	cmt   += "v{:d}[6].byte  = v{:d}[11].byte\n".format(vD, vA)
	cmt   += "v{:d}[7].byte  = v{:d}[11].byte\n".format(vD, vB)
	cmt   += "v{:d}[8].byte  = v{:d}[12].byte\n".format(vD, vA)
	cmt   += "v{:d}[9].byte  = v{:d}[12].byte\n".format(vD, vB)
	cmt   += "v{:d}[10].byte = v{:d}[13].byte\n".format(vD, vA)
	cmt   += "v{:d}[11].byte = v{:d}[13].byte\n".format(vD, vB)
	cmt   += "v{:d}[12].byte = v{:d}[14].byte\n".format(vD, vA)
	cmt   += "v{:d}[13].byte = v{:d}[14].byte\n".format(vD, vB)
	cmt   += "v{:d}[14].byte = v{:d}[15].byte\n".format(vD, vA)
	cmt   += "v{:d}[15].byte = v{:d}[15].byte".format(vD, vB)
	return cmt

def vmrglh(vD, vA, vB):

	cmt    = ".\n"
	cmt   += "v{:d}[0].half = v{:d}[4].half\n".format(vD, vA)
	cmt   += "v{:d}[1].half = v{:d}[4].half\n".format(vD, vB)
	cmt   += "v{:d}[2].half = v{:d}[5].half\n".format(vD, vA)
	cmt   += "v{:d}[3].half = v{:d}[5].half\n".format(vD, vB)
	cmt   += "v{:d}[4].half = v{:d}[6].half\n".format(vD, vA)
	cmt   += "v{:d}[5].half = v{:d}[6].half\n".format(vD, vB)
	cmt   += "v{:d}[6].half = v{:d}[7].half\n".format(vD, vA)
	cmt   += "v{:d}[7].half = v{:d}[7].half".format(vD, vB)
	return cmt

def vmrglw(vD, vA, vB):

	cmt    = ".\n"
	cmt   += "v{:d}[0].word = v{:d}[2].word\n".format(vD, vA)
	cmt   += "v{:d}[1].word = v{:d}[2].word\n".format(vD, vB)
	cmt   += "v{:d}[2].word = v{:d}[3].word\n".format(vD, vA)
	cmt   += "v{:d}[3].word = v{:d}[3].word".format(vD, vB)
	return cmt

# vmsummbm todo...

def vmulfp(vD, vA, vB):

	return "v{:d}[4xfloat] = v{:d} * v{:d}".format(vD, vA, vB)


def vmulesb(vD, vA, vB):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].half = v{:d}[0].byte * v{:d}[0].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[2].byte * v{:d}[2].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[4].byte * v{:d}[4].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[6].byte * v{:d}[6].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[8].byte * v{:d}[8].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[10].byte * v{:d}[10].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[12].byte * v{:d}[12].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[14].byte * v{:d}[14].byte".format(vD, vA, vB)
	return cmt

def vmulesh(vD, vA, vB):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].word = v{:d}[0].half * v{:d}[0].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[2].half * v{:d}[2].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[4].half * v{:d}[4].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[6].half * v{:d}[6].half".format(vD, vA, vB)
	return cmt

def vmuleub(vD, vA, vB):

	cmt    = ".\n"
	cmt  += "v{:d}[0].half = v{:d}[0].byte * v{:d}[0].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[2].byte * v{:d}[2].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[4].byte * v{:d}[4].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[6].byte * v{:d}[6].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[8].byte * v{:d}[8].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[10].byte * v{:d}[10].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[12].byte * v{:d}[12].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[14].byte * v{:d}[14].byte".format(vD, vA, vB)
	return cmt

def vmuleuh(vD, vA, vB):

	cmt    = ".\n"
	cmt  += "v{:d}[0].word = v{:d}[0].half * v{:d}[0].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[2].half * v{:d}[2].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[4].half * v{:d}[4].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[6].half * v{:d}[6].half".format(vD, vA, vB)
	return cmt

def vmulosb(vD, vA, vB):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].half = v{:d}[1].byte * v{:d}[1].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[3].byte * v{:d}[3].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[5].byte * v{:d}[5].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[7].byte * v{:d}[7].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[9].byte * v{:d}[9].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[11].byte * v{:d}[11].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[13].byte * v{:d}[13].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[15].byte * v{:d}[15].byte".format(vD, vA, vB)
	return cmt

def vmulosh(vD, vA, vB):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].word = v{:d}[1].half * v{:d}[1].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[3].half * v{:d}[3].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[5].half * v{:d}[5].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[7].half * v{:d}[7].half".format(vD, vA, vB)
	return cmt

def vmuloub(vD, vA, vB):

	cmt    = ".\n"
	cmt  += "v{:d}[0].half = v{:d}[1].byte * v{:d}[1].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[3].byte * v{:d}[3].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[5].byte * v{:d}[5].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[7].byte * v{:d}[7].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[9].byte * v{:d}[9].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[11].byte * v{:d}[11].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[13].byte * v{:d}[13].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[15].byte * v{:d}[15].byte".format(vD, vA, vB)
	return cmt

def vmulouh(vD, vA, vB):

	cmt    = ".\n"
	cmt  += "v{:d}[0].word = v{:d}[1].half * v{:d}[1].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[3].half * v{:d}[3].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[5].half * v{:d}[5].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[7].half * v{:d}[7].half".format(vD, vA, vB)
	return cmt

def vnmsubfp(vD, vA, vB, vC):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) - v{:d}".format(vD, vA, vC, vB)

def vnor(vD, vA, vB):

	return "v{:d}[4x32b] = ~(v{:d} | v{:d})".format(vD, vA, vB)

def vnot(vD, vA):

	return "v{:d}[4x32b] = ~v{:d}".format(vD, vA)

def vor(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} | v{:d}".format(vD, vA, vB)

def vmr(vD, vA):

	return "v{:d}[4x32b] = v{:d}".format(vD, vA)

def vperm(vD, vA, vB, vC):

	return ".\nfor (field = 0; field <= 15; field++)\n{{\n  x = v{:d}.byte[field]\n  if      (x & 0x10) == 0x00) {{v{:d}.byte[field] = v{:d}.byte[x & 0x0f];}}\n  else if (x & 0x10) == 0x10) {{v{:d}.byte[field] = v{:d}.byte[x & 0x0f];}}\n}}".format(vC, vD, vA, vD, vB)

def vpkpx(vD, vA, vB):

	cmt   = ".\ntemp  = (v{:d}[0-3].word >> 3) & 0x1F\n".format(vA)
	cmt  += "temp |= (v{:d}[0-3].word >> 6) & 0x3E0\n".format(vA)
	cmt  += "temp |= (v{:d}[0-3].word >> 9) & 0xFC00\n".format(vA)
	cmt  += "v{:d}[4x16b][0-3] = temp\n".format(vD)
	cmt  += "temp  = (v{:d}[0-3].word >> 3) & 0x1F\n".format(vB)
	cmt  += "temp |= (v{:d}[0-3].word >> 6) & 0x3E0\n".format(vB)
	cmt  += "temp |= (v{:d}[0-3].word >> 9) & 0xFC00\n".format(vB)
	cmt  += "v{:d}[4x16b][4-7] = temp".format(vD)
	return cmt

def vpkshss(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-7].byte  = SaturateSignedHalfToSignedByte(v{:d}[0-7].half) ".format(vD, vA)
	cmt  += "\nv{:d}[8-15].byte = SaturateSignedHalfToSignedByte(v{:d}[0-7].half) ".format(vD, vB)
	cmt  += "\nValues below -0x80 are saturated to -0x80, values above 0x7F are saturated to 0x7F"
	return cmt

def vpkshus(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-7].byte  = SaturateSignedHalfToUnsignedByte(v{:d}[0-7].half)".format(vD, vA)
	cmt  += "\nv{:d}[8-15].byte = SaturateSignedHalfToUnsignedByte(v{:d}[0-7].half)".format(vD, vB)
	cmt  += "\nValues below 0 are saturated to 0x00, values above 0xFF are saturated to 0xFF"
	return cmt

def vpkswss(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-3].half = SaturateSignedWordToSignedHalf(v{:d}[0-3].word) ".format(vD, vA)
	cmt  += "\nv{:d}[4-7].half = SaturateSignedWordToSignedHalf(v{:d}[0-3].word) ".format(vD, vB)
	cmt  += "\nValues below -0x8000 are saturated to -0x8000, values above 0x7FFF are saturated to 0x7FFF"
	return cmt
	
def vpkswus(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-3].half = SaturateSignedWordToUnsignedHalf(v{:d}[0-3].word) ".format(vD, vA)
	cmt  += "\nv{:d}[4-7].half = SaturateSignedWordToUnsignedHalf(v{:d}[0-3].word) ".format(vD, vB)
	cmt  += "\nValues below 0 are saturated to 0x0000, values above 0xFFFF are saturated to 0xFFFF"
	return cmt
	
def vpkuhum(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-7].byte  = v{:d}[0-7].half & 0xFF".format(vD, vA)
	cmt  += "\nv{:d}[8-15].byte = v{:d}[0-7].half & 0xFF".format(vD, vB)
	return cmt
	
def vpkuhus(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-7].byte  = SaturateUnsignedHalfToUnsignedByte(v{:d}[0-7].half)".format(vD, vA)
	cmt  += "\nv{:d}[8-15].byte = SaturateUnsignedHalfToUnsignedByte(v{:d}[0-7].half)".format(vD, vB)
	cmt  += "\nValues above 0xFF are saturated to 0xFF"
	return cmt

def vpkuwum(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-3].half = v{:d}[0-3].word & 0xFFFF".format(vD, vA)
	cmt  += "\nv{:d}[4-7].half = v{:d}[0-3].word & 0xFFFF".format(vD, vB)
	return cmt
	
def vpkuwus(vD, vA, vB):

	cmt   = "."
	cmt  += "\nv{:d}[0-3].half = SaturateUnsignedWordToUnsignedHalf(v{:d}[0-3].word) ".format(vD, vA)
	cmt  += "\nv{:d}[4-7].half = SaturateUnsignedWordToUnsignedHalf(v{:d}[0-3].word) ".format(vD, vB)
	cmt  += "\nValues above 0xFFFF are saturated to 0xFFFF"
	return cmt
	
# todo pack opcodes

def vrefp(vD, vB):

	return "v{:d}[4xfloat] = 1.0 / v{:d}".format(vD, vB)

def vrfim(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardNegativeInf(v{:d})".format(vD, vB)

def vrfin(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardNearest(v{:d})".format(vD, vB)

def vrfip(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardPositiveInf(v{:d})".format(vD, vB)

def vrfiz(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardZero(v{:d})".format(vD, vB)

def vrlb(vD, vA, vB):

	return "v{:d}[16x8b] = rol8(v{:d}, (v{:d} & 7))".format(vD, vA, vB)

def vrlh(vD, vA, vB):

	return "v{:d}[8x16b] = rol16(v{:d}, (v{:d} & 0xF))".format(vD, vA, vB)

def vrlw(vD, vA, vB):

	return "v{:d}[4x32b] = rol32(v{:d}, (v{:d} & 0x1F))".format(vD, vA, vB)

def vrsqrtefp(vD, vB):

	return "v{:d}[4xfloat] = 1.0 / (v{:d} * v{:d})".format(vD, vB, vB)

def vsel(vD, vA, vB, vC):

	return "[128b] if bit in v{:d} == 0 take bit from v{:d}, else take bit from v{:d}".format(vC, vA, vB)

def vsl(vD, vA, vB):

	return "v{:d}[128b] = v{:d} << (v{:d} & 7)".format(vD, vA, vB)

def vslb(vD, vA, vB):

	return "v{:d}[16x8b] = v{:d} << (v{:d} & 7)".format(vD, vA, vB)

def vsldoi(vD, vA, vB, sh):

	sh <<= 3
	shr  = 128 - sh
	return "v{:d}[128b] = (v{:d} << {:d}) | (v{:d} >> {:d})".format(vD, vA, sh, vB, shr)

def vslh(vD, vA, vB):

	return "v{:d}[8x16b] = v{:d} << (v{:d} & 0xF)".format(vD, vA, vB)

def vslo(vD, vA, vB):

	return "v{:d}[128b] = v{:d} << (v{:d} & 0x78)".format(vD, vA, vB)

def vslw(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} << (v{:d} & 0x1F)".format(vD, vA, vB)

def vspltb(vD, imm, vB):

	return "v{:d}[16x8b] = v{:d}[{:d}].byte".format(vD, vB, imm)

def vsplth(vD, imm, vB):
	
	imm &= 7
	return "v{:d}[8x16b] = v{:d}[{:d}].half".format(vD, vB, imm)

def vspltisb(vD, simm):

	neg = ""
	if simm > 0xF:
		neg = " ("
		neg += imm5_to_signed_string(simm)
		neg += ")"
	simm = sign_extend_imm5(1, simm)
	return "v{:d}[16x8b] = 0x{:02X}".format(vD, simm) + neg

def vspltish(vD, simm):

	neg = ""
	if simm > 0xF:
		neg = " ("
		neg += imm5_to_signed_string(simm)
		neg += ")"
	simm = sign_extend_imm5(2, simm)
	return "v{:d}[8x16b] = 0x{:04X}".format(vD, simm) + neg

def vspltisw(vD, simm):

	neg = ""
	if simm > 0xF:
		neg = " ("
		neg += imm5_to_signed_string(simm)
		neg += ")"
	simm = sign_extend_imm5(0, simm)
	return "v{:d}[4x32b] = 0x{:08X}".format(vD, simm) + neg

def vspltw(vD, imm, vB):
	
	imm &= 3
	return "v{:d}[4x32b] = v{:d}[{:d}].word".format(vD, vB, imm)

def vsr(vD, vA, vB):

	return "v{:d}[128b] = v{:d} >> (v{:d} & 7)".format(vD, vA, vB)

def vsrab(vD, vA, vB):

	return "v{:d}[16x8b][arithm] = v{:d} >> (v{:d} & 7)".format(vD, vA, vB)

def vsrah(vD, vA, vB):

	return "v{:d}[8x16b][arithm]= v{:d} >> (v{:d} & 0xF)".format(vD, vA, vB)

def vsraw(vD, vA, vB):

	return "v{:d}[4x32b][arithm] = v{:d} >> (v{:d} & 0x1F)".format(vD, vA, vB)

def vsrb(vD, vA, vB):

	return "v{:d}[16x8b] = v{:d} >> (v{:d} & 7)".format(vD, vA, vB)

def vsrh(vD, vA, vB):

	return "v{:d}[8x16b] = v{:d} >> (v{:d} & 0xF)".format(vD, vA, vB)

def vsro(vD, vA, vB):

	return "v{:d}[128b] = v{:d} >> (v{:d} & 0x78)".format(vD, vA, vB)

def vsrw(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} >> (v{:d} & 0x1F)".format(vD, vA, vB)

# todo vsubs

def vsubfp(vD, vA, vB):

	return "v{:d}[4xfloat] = v{:d} - v{:d}".format(vD, vA, vB)

# todo vupkhpx, vupklpx

def vupkhsb(vD, vB):

	return "v{:d}[0-7].half = SignExtendTo16(v{:d}[0-7].byte)".format(vD, vB)

def vupkhsh(vD, vB):

	return "v{:d}[0-3].word = SignExtendTo32(v{:d}[0-3].half)".format(vD, vB)

def vupklsb(vD, vB):

	return "v{:d}[0-7].half = SignExtendTo16(v{:d}[8-15].byte)".format(vD, vB)

def vupklsh(vD, vB):

	return "v{:d}[0-3].word = SignExtendTo32(v{:d}[4-7].half)".format(vD, vB)

def vxor(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} ^ v{:d}".format(vD, vA, vB)


def AltivecAsm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	
	#Altivec
	vA     = (opcode >> 16) & 0x1F
	vB     = (opcode >> 11) & 0x1F
	vC     = (opcode >> 6 ) & 0x1F
	vD     = (opcode >> 21) & 0x1F
	vS     = (opcode >> 21) & 0x1F
	imm    = (opcode >> 16) & 0x1F
	simm   = (opcode >> 16) & 0x1F
	sh     = (opcode >> 6 ) & 0xF
	vRc    = (opcode >> 10) & 1

	if   opcode_name == "vaddcuw":       return vaddcuw(vD, vA, vB)
	elif opcode_name == "vaddfp":        return vaddfp(vD, vA, vB)
	elif opcode_name == "vaddsbs":       return vaddsbs(vD, vA, vB)
	elif opcode_name == "vaddshs":       return vaddshs(vD, vA, vB)
	elif opcode_name == "vaddsws":       return vaddsws(vD, vA, vB)
	elif opcode_name == "vaddubm":       return vaddubm(vD, vA, vB)
	elif opcode_name == "vadduhm":       return vadduhm(vD, vA, vB)
	elif opcode_name == "vadduwm":       return vadduwm(vD, vA, vB)
	elif opcode_name == "vaddubs":       return vaddubs(vD, vA, vB)
	elif opcode_name == "vadduhs":       return vadduhs(vD, vA, vB)
	elif opcode_name == "vadduws":       return vadduws(vD, vA, vB)
	elif opcode_name == "vand":          return vand(vD, vA, vB)
	elif opcode_name == "vandc":         return vandc(vD, vA, vB)
	elif opcode_name == "vavgsb":        return vavgsb(vD, vA, vB)
	elif opcode_name == "vavgsh":        return vavgsh(vD, vA, vB)
	elif opcode_name == "vavgsw":        return vavgsw(vD, vA, vB)
	elif opcode_name == "vavgub":        return vavgub(vD, vA, vB)
	elif opcode_name == "vavguh":        return vavguh(vD, vA, vB)
	elif opcode_name == "vavguw":        return vavguw(vD, vA, vB)
	elif opcode_name == "vcfsx":         return vcfsx(vD, imm, vB)
	elif opcode_name == "vcfux":         return vcfux(vD, imm, vB)
	elif opcode_name == "vcmpbfp":       return vcmpbfp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpeqfp":      return vcmpeqfp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpequb":      return vcmpequb(vD, vA, vB, vRc)
	elif opcode_name == "vcmpequh":      return vcmpequh(vD, vA, vB, vRc)
	elif opcode_name == "vcmpequw":      return vcmpequw(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgefp":      return vcmpgefp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtfp":      return vcmpgtfp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtsb":      return vcmpgtsb(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtsh":      return vcmpgtsh(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtsw":      return vcmpgtsw(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtub":      return vcmpgtub(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtuh":      return vcmpgtuh(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtuw":      return vcmpgtuw(vD, vA, vB, vRc)
	elif opcode_name == "vcmpbfp.":      return vcmpbfp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpeqfp.":     return vcmpeqfp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpequb.":     return vcmpequb(vD, vA, vB, vRc)
	elif opcode_name == "vcmpequh.":     return vcmpequh(vD, vA, vB, vRc)
	elif opcode_name == "vcmpequw.":     return vcmpequw(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgefp.":     return vcmpgefp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtfp.":     return vcmpgtfp(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtsb.":     return vcmpgtsb(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtsh.":     return vcmpgtsh(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtsw.":     return vcmpgtsw(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtub.":     return vcmpgtub(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtuh.":     return vcmpgtuh(vD, vA, vB, vRc)
	elif opcode_name == "vcmpgtuw.":     return vcmpgtuw(vD, vA, vB, vRc)
	elif opcode_name == "vctsxs":        return vctsxs(vD, imm, vB)
	elif opcode_name == "vctuxs":        return vctuxs(vD, imm, vB)
	elif opcode_name == "vlogefp":       return vlogefp(vD, vB)
	elif opcode_name == "vexptefp":      return vexptefp(vD, vB)
	elif opcode_name == "vmaddfp":       return vmaddfp(vD, vA, vB, vC)
	elif opcode_name == "vmaxfp":        return vmaxfp(vD, vA, vB)
	elif opcode_name == "vmaxsb":        return vmaxsb(vD, vA, vB)
	elif opcode_name == "vmaxsh":        return vmaxsh(vD, vA, vB)
	elif opcode_name == "vmaxsw":        return vmaxsw(vD, vA, vB)
	elif opcode_name == "vmaxub":        return vmaxub(vD, vA, vB)
	elif opcode_name == "vmaxuh":        return vmaxuh(vD, vA, vB)
	elif opcode_name == "vmaxuw":        return vmaxuw(vD, vA, vB)
	elif opcode_name == "vmhaddshs":     return vmhaddshs(vD, vA, vB, vC)
	elif opcode_name == "vmhraddshs":    return vmhraddshs(vD, vA, vB, vC)
	elif opcode_name == "vminfp":        return vminfp(vD, vA, vB)
	elif opcode_name == "vminsb":        return vminsb(vD, vA, vB)
	elif opcode_name == "vminsh":        return vminsh(vD, vA, vB)
	elif opcode_name == "vminsw":        return vminsw(vD, vA, vB)
	elif opcode_name == "vminub":        return vminub(vD, vA, vB)
	elif opcode_name == "vminuh":        return vminuh(vD, vA, vB)
	elif opcode_name == "vminuw":        return vminuw(vD, vA, vB)
	elif opcode_name == "vmladduhm":     return vmladduhm(vD, vA, vB, vC)
	elif opcode_name == "vmrghb":        return vmrghb(vD, vA, vB)
	elif opcode_name == "vmrghh":        return vmrghh(vD, vA, vB)
	elif opcode_name == "vmrghw":        return vmrghw(vD, vA, vB)
	elif opcode_name == "vmrglb":        return vmrglb(vD, vA, vB)
	elif opcode_name == "vmrglh":        return vmrglh(vD, vA, vB)
	elif opcode_name == "vmrglw":        return vmrglw(vD, vA, vB)
	elif opcode_name == "vmulfp":        return vmulfp(vD, vA, vB)
	elif opcode_name == "vmulesb":       return vmulesb(vD, vA, vB)
	elif opcode_name == "vmulesh":       return vmulesh(vD, vA, vB)
	elif opcode_name == "vmuleub":       return vmuleub(vD, vA, vB)
	elif opcode_name == "vmuleuh":       return vmuleuh(vD, vA, vB)
	elif opcode_name == "vmulosb":       return vmulosb(vD, vA, vB)
	elif opcode_name == "vmulosh":       return vmulosh(vD, vA, vB)
	elif opcode_name == "vmuloub":       return vmuloub(vD, vA, vB)
	elif opcode_name == "vmulouh":       return vmulouh(vD, vA, vB)
	elif opcode_name == "vnmsubfp":      return vnmsubfp(vD, vA, vB, vC)
	elif opcode_name == "vnor":          return vnor(vD, vA, vB)
	elif opcode_name == "vnot":          return vnot(vD, vA)
	elif opcode_name == "vor":           return vor(vD, vA, vB)
	elif opcode_name == "vmr":           return vmr(vD, vA)
	elif opcode_name == "vperm":         return vperm(vD, vA, vB, vC)	
	elif opcode_name == "vpkpx":         return vpkpx(vD, vA, vB)
	elif opcode_name == "vpkshss":       return vpkshss(vD, vA, vB)
	elif opcode_name == "vpkshus":       return vpkshus(vD, vA, vB)
	elif opcode_name == "vpkswss":       return vpkswss(vD, vA, vB)
	elif opcode_name == "vpkswus":       return vpkswus(vD, vA, vB)
	elif opcode_name == "vpkuhum":       return vpkuhum(vD, vA, vB)
	elif opcode_name == "vpkuhus":       return vpkuhus(vD, vA, vB)
	elif opcode_name == "vpkuwum":       return vpkuwum(vD, vA, vB)
	elif opcode_name == "vpkuwus":       return vpkuwus(vD, vA, vB)
	elif opcode_name == "vrefp":         return vrefp(vD, vB)
	elif opcode_name == "vrfim":         return vrfim(vD, vB)
	elif opcode_name == "vrfin":         return vrfin(vD, vB)
	elif opcode_name == "vrfip":         return vrfip(vD, vB)
	elif opcode_name == "vrfiz":         return vrfiz(vD, vB)
	elif opcode_name == "vrlb":          return vrlb(vD, vA, vB)
	elif opcode_name == "vrlh":          return vrlh(vD, vA, vB)
	elif opcode_name == "vrlw":          return vrlw(vD, vA, vB)
	elif opcode_name == "vrsqrtefp":     return vrsqrtefp(vD, vB)
	elif opcode_name == "vsel":          return vsel(vD, vA, vB, vC)
	elif opcode_name == "vsl":           return vsl(vD, vA, vB)
	elif opcode_name == "vslb":          return vslb(vD, vA, vB)
	elif opcode_name == "vsldoi":        return vsldoi(vD, vA, vB, sh)
	elif opcode_name == "vslh":          return vslh(vD, vA, vB)
	elif opcode_name == "vslo":          return vslo(vD, vA, vB)
	elif opcode_name == "vslw":          return vslw(vD, vA, vB)
	elif opcode_name == "vspltb":        return vspltb(vD, imm, vB)
	elif opcode_name == "vsplth":        return vsplth(vD, imm, vB)
	elif opcode_name == "vspltisb":      return vspltisb(vD, simm)
	elif opcode_name == "vspltish":      return vspltish(vD, simm)
	elif opcode_name == "vspltisw":      return vspltisw(vD, simm)
	elif opcode_name == "vspltw":        return vspltw(vD, imm, vB)
	elif opcode_name == "vsr":           return vsr(vD, vA, vB)
	elif opcode_name == "vsrab":         return vsrab(vD, vA, vB)
	elif opcode_name == "vsrah":         return vsrah(vD, vA, vB)
	elif opcode_name == "vsraw":         return vsraw(vD, vA, vB)
	elif opcode_name == "vsrb":          return vsrb(vD, vA, vB)
	elif opcode_name == "vsrh":          return vsrh(vD, vA, vB)
	elif opcode_name == "vsro":          return vsro(vD, vA, vB)
	elif opcode_name == "vsrw":          return vsrw(vD, vA, vB)	
	elif opcode_name == "vsubfp":        return vsubfp(vD, vA, vB)	
	elif opcode_name == "vupkhsb":       return vupkhsb(vD, vB)
	elif opcode_name == "vupkhsh":       return vupkhsh(vD, vB)
	elif opcode_name == "vupklsb":       return vupklsb(vD, vB)
	elif opcode_name == "vupklsh":       return vupklsh(vD, vB)
	elif opcode_name == "vxor":          return vxor(vD, vA, vB)

	return 0
