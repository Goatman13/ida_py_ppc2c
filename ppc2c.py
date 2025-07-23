# PPC To C
#
# by working with the disassembled text this plugin should
# work with both big and little endian PPC.

from ida_bytes import *
from idaapi import *
from idc import *
import ida_ida
import idaapi
import ida_bytes
import idc
import ppc2c.altivec2c
import ppc2c.vmx128_2c
import ppc2c.gekko2c

SIMPLIFY  = 1
MASK32_ALLSET   = 0xFFFFFFFF
MASK64_ALLSET   = 0xFFFFFFFFFFFFFFFF

g_mnem = 0
g_opnd_s0 = 0
g_opnd_s1 = 0
g_opnd_s2 = 0
g_opnd_s3 = 0
g_opnd_s4 = 0

g_RA = 0
g_RS = 0
g_RB = 0
g_SH = 0
g_MB = 0
g_ME = 0


# generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
# MB and ME should be values 0 - 31
def GenerateMask32(MB, ME):
	
	if(	MB <  0 or ME <  0 or MB > 31 or ME > 31 ):
		msg("Error with paramters GenerateMask32({:d}, {:d})\n".format(MB, ME))
		return 0

	mask = 0
	if(MB < ME+1):
		# normal mask
		while MB < ME+1:
			mask = mask | (1<<(31-MB))
			MB += 1
	elif(MB == ME+1):
		# all mask bits set
		mask = MASK32_ALLSET
	elif(MB > ME+1):
		# split mask
		mask_lo = GenerateMask32(0, ME)
		mask_hi = GenerateMask32(MB, 31)
		mask = mask_lo | mask_hi

	return mask


# generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
# MB and ME should be values 0 - 63
def GenerateMask64(MB, ME):
	
	if(	MB <  0 or ME <  0 or MB > 63 or ME > 63 ):
		msg("Error with paramters GenerateMask64({:d}, {:d})\n".format(MB, ME))
		return 0

	mask = 0
	if(MB < ME+1):
		# normal mask
		while MB < ME+1:
			mask = mask | (1<<(63-MB))
			MB += 1
	elif(MB == ME+1):
		# all mask bits set
		mask = MASK64_ALLSET
	elif(MB > ME+1):
		# split mask
		mask_lo = GenerateMask64(0, ME)
		mask_hi = GenerateMask64(MB, 63)
		mask = mask_lo | mask_hi

	return mask


# generate string showing rotation or shifting within instruction
def GenerateRotate32(src, leftShift, rightShift, mask):
	
	ret_str = 0
	# work out "rotate" part of the instruction
	if(	(leftShift== 0 and rightShift==32) or (leftShift==32 and rightShift== 0 )):
		return src

	if(((MASK32_ALLSET<<leftShift ) & mask) == 0):
		# right shift only
		if((MASK32_ALLSET>>rightShift) == mask):
			mask = MASK32_ALLSET
		ret_str = src + " >> {:d}".format(rightShift)
	elif(((MASK32_ALLSET>>rightShift) & mask) == 0):
		# left shift only
		if((MASK32_ALLSET<<leftShift) == mask):
			mask = MASK32_ALLSET
		ret_str = src + " << {:d}".format(leftShift)
	else:
		# shift both ways
		ret_str = "(" + src + " << {:d}) | (".format(leftShift) + src + " >> {:d})".format(rightShift)
	return ret_str


# generate string showing rotation or shifting within instruction
def GenerateRotate64(src, leftShift, rightShift, mask):
	
	# work out "rotate" part of the instruction
	if((leftShift == 0 and rightShift == 64) or (leftShift == 64 and rightShift == 0)):
		# no rotation
		return src

	if(((MASK64_ALLSET<<leftShift ) & mask) == 0):
		# right shift only
		if((MASK64_ALLSET>>rightShift) == mask):
			mask = MASK64_ALLSET
		ret_str = src + " >> {:d}".format(rightShift)
	elif(((MASK64_ALLSET>>rightShift) & mask) == 0):
		# left shift only
		if((MASK64_ALLSET<<leftShift) == mask):
			mask = MASK64_ALLSET
		ret_str = src + " << {:d}".format(leftShift)
	else:
		# shift both ways
		ret_str = "(" + src + " << {:d}) | (".format(leftShift) + src + " >> {:d})".format(rightShift)
	return ret_str


# register rotate and immediate mask
def Rotate_iMask32(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask32(mb, me)
	if(mask == 0):
		# no rotation
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = g_RS + " << " + leftRotate + " | " + g_RS + " >> 32 - " + leftRotate
	if(mask == MASK32_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)

	# generate the resultant string
	# "%s = (%s) & %s"
	ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# immediate rotate and immediate mask
def iRotate_iMask32(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask32(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = GenerateRotate32(g_RS, leftRotate, 32-leftRotate, mask)
	if(mask == MASK32_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format(mask)
	
	# no bracelets
	if (rot_str == g_RS):
		ret_str = g_RA + " = " + rot_str + " & " + mask_str
	else:
		ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# insert immediate rotate and immediate mask
def insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask32(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = " + g_RA
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str =  GenerateRotate32(g_RS, leftRotate, 32-leftRotate, mask)
	if(mask == MASK32_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask strings
	mask_str = 0
	not_mask = 0
	not_mask_str = 0
	
	# generate mask string
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)
	
	# no bracelets
	if (rot_str == g_RS):
		ret_str = g_RA + " = (" + g_RA + " & ~" + mask_str + ") | (" + rot_str + " & " + mask_str + ")"
	else:
		ret_str = g_RA + " = (" + g_RA + " & ~" + mask_str + ") | ((" + rot_str + ") & " + mask_str + ")"
	return ret_str


# register rotate and immediate mask
def Rotate_iMask64(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask64(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = g_RS + " << " + leftRotate + " | " + g_RS + " >> 64-" + leftRotate
	if(mask == MASK64_ALLSET):
		#qsnprintf(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str)
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)

	# generate the resultant string
	ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# immediate rotate and immediate mask
def iRotate_iMask64(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask64(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = GenerateRotate64(g_RS, leftRotate, 64-leftRotate, mask)
	if(mask == MASK64_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)

	# no bracelets
	if (rot_str == g_RS):
		ret_str = g_RA + " = " + rot_str + " & " + mask_str
	else:
		ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# insert immediate rotate and immediate mask
def insert_iRotate_iMask64(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask64(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = " + g_RA
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str =  GenerateRotate64(g_RS, leftRotate, 64-leftRotate, mask)
	if(mask == MASK64_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask strings
	mask_str = 0
	not_mask = 0
	not_mask_str = 0
	
	# generate mask string
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format(mask)
	
	# no bracelets
	if (rot_str == g_RS):
		ret_str = g_RA + " = (" + g_RA + " & ~" + mask_str + ") | (" + rot_str + " & " + mask_str + ")"
	else:
		ret_str = g_RA + " = (" + g_RA + " & ~" + mask_str + ") | ((" + rot_str + ") & " + mask_str + ")"
	return ret_str

# ==================================================================
#
# helpers
#
# ==================================================================

def search_for_matching_opcode_backwards(ea, search, g_opnd_s0, g_opnd_s1, g_opnd_s2):
	
	if (SIMPLIFY == 0):
		return 0

	# Find matching opcode
	temp_ea = ea - 4
	while(temp_ea > ea - 0x20):
	
		g_mnem = print_insn_mnem(temp_ea)
		
		# Remove record bit if exist
		dot = "."
		dot = g_mnem.find(dot)
		if(dot != -1):
			g_mnem = g_mnem[0:dot]

		# Check for matching opcode
		if(g_mnem == search and print_operand(temp_ea, 0) == g_opnd_s1):
			return PPCAsm2C(temp_ea)

		temp_ea -= 4
		
	return 0


def simplify64(orig_ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME):

	if (SIMPLIFY == 0):
		return 0

	if (g_mnem == "rldicl" and  g_ME != 63 or g_SH == 0):
		return 0

	if (g_mnem in ["sldi", "extldi"] and  g_SH == 0):
		return 0
	
	# Find matching opcode
	ea = orig_ea + 4
	while(ea < orig_ea + 0x20):

		g_mnem2 = print_insn_mnem(ea)

		# Remove record bit if exist
		dot = "."
		dot = g_mnem2.find(dot)
		if(dot != -1):
			g_mnem2 = g_mnem2[0:dot]
		
		# If RA is modified earlier, we need to break and handle it old way.
		# This helps eliminate false detection when there is not paired rotxdi.
		if(print_operand(ea, 0) == g_RA):
			if ((g_mnem == "rldicl" and g_mnem2 not in ["rotldi", "rotrdi", "rldicl"])
			or (g_mnem  in ["extldi", "sldi"] and g_mnem2 != "extldi")):
				print("Rare case! " + g_mnem2 + " " + print_operand(ea, 0))
				return 0
		
		if((g_mnem == "rldicl" and g_mnem2 in ["rotldi", "rotrdi", "rldicl"])
			or (g_mnem  in ["extldi", "sldi"] and g_mnem2 == "extldi")):
			
			g_opnd_t0 = print_operand(ea, 0)
			g_opnd_t1 = print_operand(ea, 1)
			g_opnd_t2 = print_operand(ea, 2)
			if(g_mnem2 in ["rldicl", "extldi"]):
				comma = ","
				comma = g_opnd_t2.find(comma)
				if(comma != -1):
					g_opnd_t3 = g_opnd_t2[comma+1:]
					g_opnd_t2 = g_opnd_t2[0:comma]
					g_opnd_t2 = int(g_opnd_t2)
					g_opnd_t3 = int(g_opnd_t3)
			else:
				g_opnd_t2 = int(g_opnd_t2)

			# Check if next opcode is using result from first one.
			if(g_opnd_t1 == g_RA):
			
				# Check if "counter rotate" is exatcly the same as rotate.
				# This ensure compiler was trying to do one of supported operations.
				if(g_mnem == "rldicl" and g_mnem2 in ["rotldi", "rldicl"] and g_opnd_t2 != 64-g_SH):
					return 0
				elif(g_mnem == "rldicl" and g_mnem2 == "rotrdi" and g_opnd_t2 != g_SH):
					return 0
				elif(g_mnem in ["sldi", "extldi"] and g_opnd_t3 + g_SH != 64):
					return 0

				mask = GenerateMask64(g_MB, g_ME)
				mask = ((mask >> g_SH) | (mask << (64-g_SH))) & MASK64_ALLSET

				if (g_mnem == "rldicl"):
					mask = ~mask & MASK64_ALLSET
					upper_mask = mask >> 32
					lower_mask = mask & MASK32_ALLSET
					tilde = "~"
					if(g_mnem2 == "rldicl"):
						new_mask = GenerateMask64(g_opnd_t3, 63)
						new_mask = ~new_mask & MASK64_ALLSET
						new_upper_mask = new_mask >> 32
						new_lower_mask = new_mask & MASK32_ALLSET
						upper_mask = new_upper_mask | upper_mask
						lower_mask = new_lower_mask | lower_mask
						upper_mask = ~upper_mask & MASK32_ALLSET
						lower_mask = ~lower_mask & MASK32_ALLSET
						tilde = ""

				elif(g_mnem in ["sldi", "extldi"] and g_mnem2 == "extldi"):
					new_mask = GenerateMask64(0, g_opnd_t2-1)
					mask = mask & new_mask
					upper_mask = mask >> 32
					lower_mask = mask & MASK32_ALLSET
					tilde = ""

				first_mnem_comment = "Paired with " + g_mnem2 + " at 0x{:X}".format(ea)
				if(upper_mask != 0):
					second_mnem_comment = g_opnd_t0 + " = " + g_RS + " & " + tilde + "0x{:X}_{:08X} (".format(upper_mask, lower_mask) + g_RS + " from 0x{:X})".format(orig_ea)
				else:
					second_mnem_comment = g_opnd_t0 + " = " + g_RS + " & " + tilde + "0x{:X} (".format(lower_mask) + g_RS + " from 0x{:X})".format(orig_ea)					
				set_cmt(ea, second_mnem_comment, 0)
				set_cmt(orig_ea        , first_mnem_comment, 0)
				return 1

		ea += 4
	
	# matching opcode not found, fallback to default handling.
	return 0


def rlwinm_andnot(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME):

	if (SIMPLIFY == 0 or g_ME != 31 or g_SH == 0):
		return 0

	mask = GenerateMask32(g_MB, g_ME)
	mask = ((mask >> g_SH) | (mask << (32-g_SH))) & MASK32_ALLSET
	mask = ~mask & MASK32_ALLSET

	# Find matching rotxwi
	rotea = ea + 4
	while(rotea < ea + 0x20):

		# Remove record bit if exist
		is_rotxwi = print_insn_mnem(rotea)[:6]
		
		# If rlwinm RA is modified earlier, we need to break and handle it old way.
		# This helps eliminate false detection when there is not paired rotxwi.
		if(print_operand(rotea, 0) == g_RA and is_rotxwi != "rotlwi" and is_rotxwi != "rotrwi"):
				print("Rare case!")
				return 0
		
		if(is_rotxwi == "rotlwi" or is_rotxwi == "rotrwi"):
			g_opnd_t0 = print_operand(rotea, 0)
			g_opnd_t1 = print_operand(rotea, 1)
			g_opnd_t2 = int(print_operand(rotea, 2))

			# Check if rotate is using result from rlwinm
			if(g_opnd_t1 == g_RA):
			
				# Check if "counter rotate" is exatcly the same as rotate in rlwinm.
				# This ensure compiler was trying to do "and not".
				if(is_rotxwi == "rotlwi" and g_opnd_t2 != 32-g_SH):
					return 0
				elif(is_rotxwi == "rotrwi" and g_opnd_t2 != g_SH):
					return 0
					
				rlwinm_comment = "Paired with " + is_rotxwi + " at 0x{:X}".format(rotea)
				rotxwi_comment = g_opnd_t0 + " = " + g_RS + " & ~0x{:X} (".format(mask) + g_RS + " from 0x{:X})".format(ea)
				set_cmt(rotea, rotxwi_comment, 0)
				set_cmt(ea   , rlwinm_comment, 0)
				return 1

		rotea += 4
	
	# rotxwi not found, fallback to default handling.
	return 0

def get_my_cr_string(cr):
	
	if cr[0:2] == "4*":
		return cr[2:5] + ":" + cr[6:8]
	else:
		return "cr0:" + cr


# ==================================================================
#
# instructions
#
# ==================================================================

def clrlwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Clear left immediate
	# clrlwi RA, RS, n
	# rlwinm RA, RS, 0, n, 31
	g_SH = 0
	g_MB = n
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrldi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate Left Double Word Immediate then Clear Left
	# clrldi RA, RS, n
	# rldicl RA, RS, 0, n
	g_SH = 0
	g_MB = n
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrrwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Clear right immediate
	# clrrwi RA, RS, n
	# rlwinm RA, RS, 0, 0, 31-n
	g_SH = 0
	g_MB = 0
	g_ME = 31-n

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrrdi(ea, g_mnem, g_RA, g_RS, n):
	
	# Clear right immediate
	# clrrdi RA, RS, n
	# rldicr RA, RS, 0, 63 - n
	g_SH = 0
	g_MB = 0
	g_ME = 63-n

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrlslwi(ea, g_mnem, g_RA, g_RS, b, n):
	
	# Clear left word and shift left immediate
	# clrlslwi RA, RS, b, n
	# rlwinm RA, RS, b-n, 31-n
	g_SH = n
	g_MB = b-n
	g_ME = 31-n

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrlsldi(ea, g_mnem, g_RA, g_RS, b, n):
	
	# Clear left double word and shift left immediate
	# clrlsldi RA, RS, b, n
	# rldic RA, RS, n, b - n
	g_SH = n
	g_MB = b-n
	g_ME = 63-n

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extrwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Extract and right justify immediate
	# extrwi RA, RS, n, b
	# rlwinm RA, RS, b+n, 32-n, 31
	g_SH = b+n
	g_MB = 32-n
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extrdi(ea, g_mnem, g_RA, g_RS, n ,b):
	
	# Extract double word and right justify immediate
	# extrdi RA, RS, n, b
	# rldicl RA, RS, b + n, 64 - n
	g_SH = b+n
	g_MB = 64-n
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extlwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Extract and left justify immediate
	# extlwi RA, RS, n, b
	# rlwinm RA, RS, b, 0, n-1
	g_SH = b
	g_MB = 0
	g_ME = n-1

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extldi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Extract double word and left justify immediate
	# extldi RA, RS, n, b
	# rldicr RA, RS, b, n - 1
	g_SH = b
	g_MB = 0
	g_ME = n-1

	if(simplify64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME) == 1):
		return 1
	
	if(search_for_matching_opcode_backwards(ea, "sldi", g_RA, g_RS, n) == 1):
		return 1

	if(search_for_matching_opcode_backwards(ea, "extldi", g_RA, g_RS, n) == 1):
		return 1

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def inslwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Insert from left immediate
	# inslwi RA, RS, n, b
	# rlwimi RA, RS, 32-b, b, (b+n)-1
	g_SH = 32-b
	g_MB = b
	g_ME = b+n-1

	return insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def insrwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Insert from right immediate
	# insrwi RA, RS, n, b
	# rlwimi RA, RS, 32-(b+n), b, (b+n)-1
	g_SH = 32-(b+n)
	g_MB = b
	g_ME = b+n-1

	return insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def insrdi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Insert double word from right immediate
	# insrdi RA, RS, n, b
	# rldimi RA, RS, 64 - (b + n), b
	g_SH = 64-(b+n)
	g_MB = b
	g_ME = b+n-1

	return insert_iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rlwinm(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME):
	
	# Rotate Left Word Immediate Then AND with Mask
	# rlwinm RA, RS, SH, MB, ME
	
	if (rlwinm_andnot(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME) == 1):
		return 1

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rlwnm(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME):
	
	# Rotate Left Word Then AND with Mask
	# rlwnm RA, RS, RB, MB, ME

	return Rotate_iMask32(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def rotlwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate left immediate
	# rotlwi RA, RS, n
	# rlwinm RA, RS, n, 0, 31
	g_SH = n
	g_MB = 0
	g_ME = 31
	
	if(search_for_matching_opcode_backwards(ea, "rlwinm", g_RA, g_RS, n) == 1):
		return 1

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rotrwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate right immediate
	# rotrwi RA, RS, n
	# rlwinm RA, RS, 32-n, 0, 31
	g_SH = 32-n
	g_MB = 0
	g_ME = 31

	if(search_for_matching_opcode_backwards(ea, "rlwinm", g_RA, g_RS, n) == 1):
		return 1
		
	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rotldi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate left immediate
	# rotldi RA, RS, n
	# rldicl RA, RS, n, 0
	g_SH = n
	g_MB = 0
	g_ME = 63

	if(search_for_matching_opcode_backwards(ea, "rldicl", g_RA, g_RS, n) == 1):
		return 1

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rotrdi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate right immediate
	# rotrdi RA, RS, n
	# rldicl RA, RS, 64 - n, 0
	g_SH = 64-n
	g_MB = 0
	g_ME = 63

	if(search_for_matching_opcode_backwards(ea, "rldicl", g_RA, g_RS, n) == 1):
		return 1

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rotlw(ea, g_mnem, g_RA, g_RS, g_RB):
	
	# Rotate left
	# rotlw RA, RS, RB
	# rlwnm RA, RS, RB, 0, 31
	g_MB = 0
	g_ME = 31

	return Rotate_iMask32(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def rotld(ea, g_mnem, g_RA, g_RS, g_RB):
	
	# Rotate Left Double Word
	# rotld RA, RS, RB
	# rldcl RA, RS, RB, 0
	g_MB = 0
	g_ME = 63

	return Rotate_iMask64(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def rldcr(ea, g_mnem, g_RA, g_RS, g_RB, g_ME):
	
	# Rotate Left Double Word then Clear Right
	# rldcr RA, RS, RB, ME
	g_MB = 0

	return Rotate_iMask64(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def rldic(ea, g_mnem, g_RA, g_RS, g_SH, g_MB):
	
	# Rotate Left Double Word Immediate then Clear
	# rldic RA, RS, SH, MB
	g_ME = 63 - g_SH

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rldicl(ea, g_mnem, g_RA, g_RS, g_SH, g_MB):
	
	# Rotate Left Double Word Immediate then Clear Left
	# rldicl RA, RS, SH, MB
	g_ME = 63
	
	if (simplify64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME) == 1):
		return 1
	
	if(search_for_matching_opcode_backwards(ea, "rldicl", g_RA, g_RS, g_SH) == 1):
		return 1
	
	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rldicr(ea, g_mnem, g_RA, g_RS, g_SH, g_ME):
	
	# Rotate Left Double Word Immediate then Clear Right
	# rldicr RA, RS, SH, ME
	g_MB = 0

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rldimi(ea, g_mnem, g_RA, g_RS, g_SH, g_MB):
	
	# Rotate Left Double Word Immediate then Mask Insert
	# rldimi RA, RS, SH, MB
	g_ME = 63 - g_SH

	return insert_iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rlwimi(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME):
	
	# Rotate Left Word Immediate Then Mask Insert
	# rlwimi RA, RS, SH, MB, ME

	return insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def slwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift left immediate
	# slwi RA, RS, n
	# rlwinm RA, RS, n, 0, 31-n
	g_SH = n
	g_MB = 0
	g_ME = 31-n

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def srwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift right immediate
	# srwi RA, RS, n
	# rlwinm RA, RS, 32-n, n, 31
	g_SH = 32-n
	g_MB = n
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def sldi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift left double word immediate
	# sldi RA, RS, n
	# rldicr RA, RS, n, 63 - n
	g_SH = n
	g_MB = 0
	g_ME = 63-n

	if (simplify64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME) == 1):
		return 1

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def srdi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift right double word immediate
	# srdi RA, RS, n
	# rldicl RA, RS, 64 - n, n
	g_SH = 64-n
	g_MB = n
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def mfocrf(ea, g_mnem, g_RT, g_FXM):
	
	# Move from One Condition Register Field
	# mfocrf RT, FXM

	#FXM is passed as str
	g_FXM  = int(g_FXM, 16)
	if ida_ida.inf_get_procname() != "ppcl":
		if g_FXM & 0x01 != 0:
			string = " = cr7 & 0x0000000F\nbit28 = LT, bit29 = GT, bit30 = EQ, bit31 = SO"
		elif g_FXM & 0x02 != 0:
			string = " = (cr6 << 4) & 0x000000F0\nbit24 = LT, bit25 = GT, bit26 = EQ, bit27 = SO"
		elif g_FXM & 0x04 != 0:
			string = " = (cr5 << 8) & 0x00000F00\nbit20 = LT, bit21 = GT, bit22 = EQ, bit23 = SO"
		elif g_FXM & 0x08 != 0:
			string = " = (cr4 << 12) & 0x0000F000\nbit16 = LT, bit17 = GT, bit18 = EQ, bit19 = SO"
		elif g_FXM & 0x10 != 0:
			string = " = (cr3 << 16) & 0x000F0000\nbit12 = LT, bit13 = GT, bit14 = EQ, bit15 = SO"
		elif g_FXM & 0x20 != 0:
			string = " = (cr2 << 20) & 0x00F00000\nbit8 = LT, bit9 = GT, bit10 = EQ, bit11 = SO"
		elif g_FXM & 0x40 != 0:
			string = " = (cr1 << 24) & 0x0F000000\nbit4 = LT, bit5 = GT, bit6 = EQ, bit7 = SO"
		elif g_FXM & 0x80 != 0:
			string = " = (cr0 << 28) & 0xF0000000\nbit0 = LT, bit1 = GT, bit2 = EQ, bit3 = SO"
		else:
			return 0
	return ".\n" + g_RT + string

def mtocrf(ea, g_mnem, g_FXM, g_RS):
	
	# Move from One Condition Register Field
	# mfocrf RT, FXM

	#FXM is passed as str
	g_FXM  = int(g_FXM, 16)
	if ida_ida.inf_get_procname() != "ppcl":
		if g_FXM & 0x01 != 0:
			return "cr7 = " + g_RS + " & 0x0000000F (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x02 != 0:
			return "cr6 = " + g_RS + " & 0x000000F0 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x04 != 0:
			return "cr5 = " + g_RS + " & 0x00000F00 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x08 != 0:
			return "cr4 = " + g_RS + " & 0x0000F000 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x10 != 0:
			return "cr3 = " + g_RS + " & 0x000F0000 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x20 != 0:
			return "cr2 = " + g_RS + " & 0x00F00000 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x40 != 0:
			return "cr1 = " + g_RS + " & 0x0F000000 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		elif g_FXM & 0x80 != 0:
			return "cr0 = " + g_RS + " & 0xF0000000 (1 = LT, 2 = GT, 4 = EQ, 8 = SO)"
		else:
			return 0

	#LE new impl
	#if g_FXM & 0x01 != 0:
	#	string = " = (cr7 << 28) & 0xF0000000\nbit0 = LT, bit1 = GT, bit2 = EQ, bit3 = SO"
	#elif g_FXM & 0x02 != 0:
	#	string = " = (cr6 << 24) & 0x0F000000\nbit4 = LT, bit5 = GT, bit6 = EQ, bit7 = SO"
	#elif g_FXM & 0x04 != 0:
	#	string = " = (cr5 << 20) & 0x00F00000\nbit8 = LT, bit9 = GT, bit10 = EQ, bit11 = SO"
	#elif g_FXM & 0x08 != 0:
	#	string = " = (cr4 << 16) & 0x000F0000\nbit12 = LT, bit13 = GT, bit14 = EQ, bit15 = SO"
	#elif g_FXM & 0x10 != 0:
	#	string = " = (cr3 << 12) & 0x0000F000\nbit16 = LT, bit17 = GT, bit18 = EQ, bit19 = SO"
	#elif g_FXM & 0x20 != 0:
	#	string = " = (cr2 << 8) & 0x00000F00\nbit20 = LT, bit21 = GT, bit22 = EQ, bit23 = SO"
	#elif g_FXM & 0x40 != 0:
	#	string = " = (cr1 << 4) & 0x000000F0\nbit24 = LT, bit25 = GT, bit26 = EQ, bit27 = SO"
	#elif g_FXM & 0x80 != 0:
	#	string = " = cr0 & 0x0000000F\nbit28 = LT, bit29 = GT, bit30 = EQ, bit31 = SO"
	#else:
	#	return 0

def mfcr(ea, g_mnem, g_RT):

	string = ".\n"
	string += "cr7 bit28 = LT, bit29 = GT, bit30 = EQ, bit31 = SO\n"
	string += "cr6 bit24 = LT, bit25 = GT, bit26 = EQ, bit27 = SO\n"
	string += "cr5 bit20 = LT, bit21 = GT, bit22 = EQ, bit23 = SO\n"
	string += "cr4 bit16 = LT, bit17 = GT, bit18 = EQ, bit19 = SO\n"
	string += "cr3 bit12 = LT, bit13 = GT, bit14 = EQ, bit15 = SO\n"
	string += "cr2 bit8  = LT, bit9  = GT, bit10 = EQ, bit11 = SO\n"
	string += "cr1 bit4  = LT, bit5  = GT, bit6  = EQ, bit7  = SO\n"
	string += "cr0 bit0  = LT, bit1  = GT, bit2  = EQ, bit3  = SO\n"
	return string
	
def crnor(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register NOR

	return g_BD + " = ~(" + g_BA + " | " + g_BB + ")"

def crnot(ea, g_mnem, g_BD, g_BA):
	
	# Condition Register NOT

	return g_BD + " = ~" + g_BA

def crandc(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register ANDC

	return g_BD + " = " + g_BA + " & ~" + g_BB

def crxor(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register XOR

	return g_BD + " = " + g_BA + " ^ " + g_BB

def crclr(ea, g_mnem, g_BD):
	
	# Condition Register CLEAR

	return g_BD + " = 0"

def crnand(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register NAND

	return g_BD + " = ~(" + g_BA + " & " + g_BB + ")"

def crand(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register AND

	return g_BD + " = " + g_BA + " & " + g_BB
	
def creqv(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register Equivalent

	return g_BD + " = ~(" + g_BA + " ^ " + g_BB + ")"
	
def crset(ea, g_mnem, g_BD):
	
	# Condition Register SET

	return g_BD + " = 1"
	
def crorc(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register ORC

	return g_BD + " = " + g_BA + " | ~" + g_BB
	
def cror(ea, g_mnem, g_BD, g_BA, g_BB):
	
	# Condition Register OR

	return g_BD + " = " + g_BA + " | " + g_BB
	
def crmove(ea, g_mnem, g_BD, g_BA):
	
	# Condition Register MOVE

	return g_BD + " = " + g_BA
	
	
# try to do as much work in this function as possible in order to
# simplify each "instruction" handling function
def PPCAsm2C(ea):
	
	# make sure address is valid and that it points to the start of an instruction
	if(ea == BADADDR):
		return False
	if(is_code(ida_bytes.get_flags(ea)) == 0):
		return False

	# get instruction mnemonic
	g_mnem = print_insn_mnem(ea)
	if(g_mnem == 0):
		return False
	
	# Remove record bit if exist,
	# we need to do this before testing for opcode validity.
	dot = "."
	dot = g_mnem.find(dot)
	if(dot != -1):
		g_mnem = g_mnem[0:dot]
	
	is_ok = False
	accepted = ["clrlwi", "clrldi", "clrrwi", "clrrdi", "clrlslwi", "clrlsldi",
				"extlwi", "extldi", "extrwi", "extrdi", "inslwi", "insrwi", "insrdi",
				"rlwinm", "rlwnm", "rotlw", "rotlwi", "rotrwi", "rotldi", "rotld", "rotrdi", "slwi", "srwi", "sldi",
				"srdi", "rldcr", "rldic", "rldicl", "rldicr", "rldimi", "rlwimi", "mfocrf", "mtocrf", "mfcr",
				"crnor", "crnot", "crandc", "crxor", "crclr", "crnand", "crand", "creqv", "crset", "crorc", "cror", "crmove"]
	for x in accepted:
		if (g_mnem == x):
			is_ok = True
			break
	if (is_ok == False):
		return False

	# get instruction operand strings
	# IDA only natively supports 3 operands
	g_opnd_s0 = print_operand(ea, 0)
	g_opnd_s1 = print_operand(ea, 1)
	g_opnd_s2 = print_operand(ea, 2)

	# use some string manipulation to extract additional operands
	# when more than 3 operands are used
	g_opnd_s4 = 0
	g_opnd_s3 = 0
	comma1 = ","
	comma1 = g_opnd_s2.find(comma1)
	if(comma1 != -1):
		# operand-3 exists
		g_opnd_s3 = g_opnd_s2[comma1+1:]
		g_opnd_s2 = g_opnd_s2[0:comma1]
		
		comma2 = ","
		comma2 = g_opnd_s3.find(comma2)
		if(comma2 != -1):
				# operand-4 exists
			g_opnd_s4 = g_opnd_s3[comma2+1:]
			g_opnd_s3 = g_opnd_s3[0:comma2]
			g_opnd_s4 = int(g_opnd_s4)
		g_opnd_s3 = int(g_opnd_s3)
	
	# convert s2 to int, except when s2 is reg nr.
	if (g_mnem not in ["rldcr", "rotlw",  "rotld", "rlwnm", "mfocrf", "mtocrf", "mfcr",
						"crnor", "crnot", "crandc", "crxor", "crclr", "crnand", 
						"crand", "creqv", "crset", "crorc", "cror", "crmove"]):
		g_opnd_s2 = int(g_opnd_s2)
		
	# below is a list of supported instructions
	
	# clear
	if(g_mnem == "clrlwi"):
		return clrlwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrldi"):
		return clrldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrrwi"):
		return clrrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrrdi"):
		return clrrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrlslwi"):
		return clrlslwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "clrlsldi"):
		return clrlsldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	
	# extract
	elif(g_mnem == "extlwi"):
		return extlwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "extldi"):
		return extldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "extrwi"):
		return extrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "extrdi"):
		return extrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	
	# insert
	elif(g_mnem == "inslwi"):
		return inslwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "insrwi"):
		return insrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "insrdi"):
		return insrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)

	# rotate and insert
	elif(g_mnem == "rlwimi"):
		return rlwimi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3, g_opnd_s4)
	elif(g_mnem == "rldimi"):
		return rldimi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	
	# rotate and mask
	elif(g_mnem == "rlwinm"):
		return rlwinm(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3, g_opnd_s4)
	elif(g_mnem == "rlwnm"):
		return rlwnm(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3, g_opnd_s4)
	
	# rotate and clear
	elif(g_mnem == "rldcr"):
		return rldcr(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldic"):
		return rldic(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldicl"):
		return rldicl(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldicr"):
		return rldicr(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)

	# rotate
	elif(g_mnem == "rotlw"):
		return rotlw(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotlwi"):
		return rotlwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotrwi"):
		return rotrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotld"):
		return rotld(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotldi"):
		return rotldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotrdi"):
		return rotrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
		
	# shift
	elif(g_mnem == "slwi"):
		return slwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "srwi"):
		return srwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "sldi"):
		return sldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "srdi"):
		return srdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)

	# cr operations
	elif(g_mnem == "mfocrf"):
		return mfocrf(ea, g_mnem, g_opnd_s0, g_opnd_s1)
	elif(g_mnem == "mtocrf"):
		return mtocrf(ea, g_mnem, g_opnd_s0, g_opnd_s1)
	elif(g_mnem == "mfcr"):
		return mfcr(ea, g_mnem, g_opnd_s0)
	elif(g_mnem == "crnor"):
		return crnor(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "crnot"):
		return crnot(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1))
	elif(g_mnem == "crandc"):
		return crandc(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "crxor"):
		return crxor(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "crclr"):
		return crclr(ea, g_mnem, get_my_cr_string(g_opnd_s0))
	elif(g_mnem == "crnand"):
		return crnand(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "crand"):
		return crand(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "creqv"):
		return creqv(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "crset"):
		return crset(ea, g_mnem, get_my_cr_string(g_opnd_s0))
	elif(g_mnem == "crorc"):
		return crorc(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "cror"):
		return cror(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1), get_my_cr_string(g_opnd_s2))
	elif(g_mnem == "crmove"):
		return crmove(ea, g_mnem, get_my_cr_string(g_opnd_s0), get_my_cr_string(g_opnd_s1))
	return 0


def run_task(start_addr, end_addr, always_insert_comment):

	# convert all instructions within the bounds
	addr = start_addr
	while(addr < end_addr):
		print_str = PPCAsm2C(addr)
		if(print_str != 0 and print_str != 1):
			set_cmt(addr, print_str, False)
		elif (print_str == 0):
			try:
				print_str = ppc2c.altivec2c.AltivecAsm2C(addr)
			except:
				print_str = 0
				msg("[ppc2c]: WARNING! Issue occured in altivec2c.py file!\n[ppc2c]: Altivec/VMX can't be interpreted!")
			if(print_str != 0):
				set_cmt(addr, print_str, False)
			elif (print_str == 0):
				try:
					print_str = ppc2c.gekko2c.GekkoAsm2C(addr)
				except:
					print_str = 0
					msg("[ppc2c]: WARNING! Issue occured in gekko2c.py file!\n[ppc2c]: Gekko paired singles instructions can't be interpreted!")
				if(print_str != 0):
					set_cmt(addr, print_str, False)
				elif (print_str == 0):
					try:
						print_str = ppc2c.vmx128_2c.Vmx128Asm2C(addr)
					except:
						print_str = 0
						msg("[ppc2c]: WARNING! Issue occured in vmx128_2c.py file is missing!\n[ppc2c]: VMX128 can't be interpreted!")
					if(print_str != 0):
						set_cmt(addr, print_str, False)
					if(print_str == 0 and always_insert_comment == True):
						msg("[ppc2c]: At address: 0x{:X}. Error converting PPC to C code\n".format(addr))

		addr += 4 


def PluginMain():
	
	# select current line or selected lines
	always_insert_comment = False
	start_addr = read_selection_start()
	end_addr = read_selection_end()
	if(start_addr == BADADDR):
		start_addr = get_screen_ea();
		end_addr = start_addr + 4;
		always_insert_comment = True
	
	run_task(start_addr, end_addr, always_insert_comment)


def PluginMainF():
	
	# convert current function
	p_func = get_func(get_screen_ea());
	if(type(p_func) == type(None)):
		msg("Not in a function, so can't do PPC to C conversion for the current function!\n");
		return;
	start_addr = p_func.start_ea;
	end_addr = p_func.end_ea;
	always_insert_comment = False;
	
	run_task(start_addr, end_addr, always_insert_comment)


#/***************************************************************************************************
#*
#*	Strings required for IDA Pro's PLUGIN descriptor block
#*
#***************************************************************************************************/
#
G_PLUGIN_COMMENT = "PPC To C Conversion Assist"
G_PLUGIN_HELP = "This plugin assists in converting PPC instructions into their relevant C code.\nIt is especially useful for the tricky bit manipulation and shift instructions.\n"
G_PLUGIN_NAME = "PPC To C: Selected Lines"

#/***************************************************************************************************
#*
#*	This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
#*
#***************************************************************************************************/

class ActionHandler(idaapi.action_handler_t):

    def __init__(self, callback):
        
        idaapi.action_handler_t.__init__(self)
        self.callback = callback
    
    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):
        
        return idaapi.AST_ENABLE_ALWAYS

def register_actions():   

    actions = [
        {
            'id': 'start:plg',
            'name': G_PLUGIN_NAME,
            'hotkey': 'F10',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMain,
            'menu_location': 'Start Plg'
        },
        {
            'id': 'start:plg1',
            'name': 'pypyc2c unimplemented',
            'hotkey': 'Alt-Shift-F10',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMainF,
            'menu_location': 'Start Plg1'
        }
    ]

    for action in actions:

        if not idaapi.register_action(idaapi.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        if not idaapi.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            0):

            print('Failed to attach to menu '+ action['id'])

class ppc_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = G_PLUGIN_COMMENT
	help = G_PLUGIN_HELP
	wanted_name = G_PLUGIN_NAME
	wanted_hotkey = "F10"

	def init(self):
		if (idaapi.ph.id == idaapi.PLFM_PPC):
			register_actions()
			idaapi.msg("[ppc2c]: loaded\n")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		pass
	def term(self):
		pass

def PLUGIN_ENTRY():
	return ppc_helper_t()